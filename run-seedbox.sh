#!/bin/bash

set -eEuo pipefail

SKIP_PULL=0
DEBUG=0
TMP_FOLDER=$(mktemp -d -p. .seedbox-tmp.XXX)
CONFIG_JSON_FILE="$TMP_FOLDER/config.json"

# Docker-compose settings
export COMPOSE_HTTP_TIMEOUT=240

for ARG in "$@"; do
    case "$ARG" in
    --no-pull)
        SKIP_PULL=1
        ;;
    --debug)
        DEBUG=1
        ;;
    *)
        fatal "Unknown parameter '$ARG'"
        ;;
    esac
done

# shellcheck disable=SC2329
cleanup_on_exit() {
  rm -rf -- "$TMP_FOLDER"
}
trap cleanup_on_exit EXIT

fatal() {
    echo "[-] ❌ ERROR:" "$@" 1>&2
    exit 1
}

echo-debug() {
    if [[ "$DEBUG" == "1" ]]; then
        echo "$@" >&2
    fi
}

preflight_checks() {
    if [[ ! -f .env ]]; then
        fatal "No 'env' file found."
    fi

    if [[ ! -f .env.custom ]]; then
        fatal "No '.env.custom' file found."
    fi

    if [[ ! -f docker-compose.yaml ]]; then
        fatal "No 'docker-compose.yaml' file found."
    fi

    if [[ ! -f config.yaml ]]; then
        fatal "No 'config.yaml' file found."
    fi
}

# Sanitize and extract variable (without prefixes) from .env.custom file
# Input => $1 = app name (exemple traefik)
# Output => env/app_name.env written with correct variables (exemple: env/traefik.env)
extract_custom_env_file() {
  local app_name="$1"
  
  if [[ -z "$app_name" ]]; then
    fatal "extract_custom_env_file: app_name argument is empty or not provided"
  fi
  
  local app_prefix="${app_name^^}_"
  local output_file="env/${app_name}.env"
  
  # sed explanation:
  #   1 => Keep only lines starting with [uppercase_app_name + "_"] (example: TRAEFIK_)
  #   2 => Remove the pattern [uppercase_app_name + "_"] and print the result
  sed -n -e "/^${app_prefix}/s/^${app_prefix}//p" .env.custom > "$output_file"
}

# Check if a service ($1) has been enabled in the config file
is_service_enabled() {
    local service="$1" count

    count=$(jq --arg service "$service" '[.services[] | select(.name==$service and .enabled==true)] | length' "$CONFIG_JSON_FILE")
    
    case "$count" in
        0) return 1 ;;
        1) return 0 ;;
        *) fatal "Service \"$service\" is enabled more than once. Check your config.yaml file." ;;
    esac
}

is_gluetun_enabled() {
    local count

    # Check if some services have vpn enabled, that gluetun itself is enabled
    count=$(jq '[.services[] | select(.enabled==true and .vpn==true)] | length' "$CONFIG_JSON_FILE")
    
    if [[ ${count} -gt 0 ]] && ! is_service_enabled gluetun; then
        fatal "${count} VPN-enabled services have been enabled BUT gluetun has not been enabled. Please check your config.yaml file."
    fi
}

is_authelia_enabled() {
    local count

    # Check if some services have sso enabled, that authelia itself is enabled
    count=$(jq '[.services[] | select(.enabled==true and .traefik.rules[].sso==true)] | length' "$CONFIG_JSON_FILE")
   
    if [[ ${count} -gt 0 ]] && ! is_service_enabled authelia; then
        fatal "${count} Authelia-enabled services have been enabled BUT authelia itself has not been enabled. Please check your config.yaml file."
    fi
}

is_sso_not_mixed_with_httpAuth() {
    local count

    # Check that for a same rule, httpAuth and authelia are not both enabled
    count=$(jq '[.services[] | select(.traefik.rules[].httpAuth==true and .traefik.rules[].sso==true)] | length' "$CONFIG_JSON_FILE")
    if [[ ${count} -gt 0 ]]; then
        fatal "${count} services have both SSO/Authelia and HTTP Authentication enabled. Please choose only one for a rule."
    fi
}

###############################################################################################
####################################### MAIN ##################################################
###############################################################################################

preflight_checks

mkdir -p env
#shellcheck disable=SC1091
source .env
yq eval -o json config.yaml > "$CONFIG_JSON_FILE"

is_gluetun_enabled
is_authelia_enabled
is_sso_not_mixed_with_httpAuth

###############################################################################################
####################################### SERVICES PARSING ######################################
###############################################################################################

echo "***** Generating configuration... *****"
truncate -s0 "$HOME/.seedbox_services"

ALL_SERVICES=("-f docker-compose.yaml")
TOTAL_SERVICES=$(jq '.services | length' "$CONFIG_JSON_FILE")
SERVICE_INDEX=0

while read -r json; do
    # Progress indicator with constant width
    printf "***** Processing [%02d / %02d] *****\r" "$((++SERVICE_INDEX))" "$TOTAL_SERVICES"
    # Break progress line if loop is ending
    if [[ "$SERVICE_INDEX" -eq "$TOTAL_SERVICES" ]]; then
        echo ""
    fi
    
    enabled=$(jq -r .enabled <<< "$json")
    # Skip disabled services
    if [[ ${enabled} == "false" ]]; then
        echo-debug "Service $name is disabled. Skipping it."
        continue
    fi

    name=$(jq -r .name <<< "$json")
    file="$name.yaml"
    vpn=$(jq -r .vpn <<< "$json")
    customFile=$(jq -r .customFile <<< "$json")

    if [[ ${customFile} != "null" ]]; then 
        file=${customFile}
    fi

    echo-debug "➡️ Parsing service: '$name' with file: '$file'..."
    echo -n "$name " >> "$HOME/.seedbox_services"

    # Append $file to global list of files which will be passed to docker commands
    ALL_SERVICES+=("-f services/${file}")

    # For services with VPN enabled, add a docker-compose "override" file specifying that the service network should
    # go through gluetun (main vpn client service).
    if [[ ${vpn} == "true" ]]; then
        yq -p=props -o yaml <<< "services.${name}.network_mode: service:gluetun" > "services/generated/${name}-vpn.yaml"
        # Append config/${name}-vpn.yaml to global list of files which will be passed to docker commands
        ALL_SERVICES+=("-f services/generated/${name}-vpn.yaml")
    fi

    # For services with existing custom environment variables in .env.custom, 
    # Extract those variables and add a docker-compose override file in order to load them
    if grep -q "^${name^^}_" .env.custom; then
        extract_custom_env_file "${name}"
        yq -p=props -o yaml <<< "services.${name}.env_file.0: ./env/${name}.env" > "services/generated/${name}-envfile.yaml"
        # Append config/${name}-envfile.yaml to global list of files which will be passed to docker commands
        ALL_SERVICES+=("-f services/generated/${name}-envfile.yaml")
    fi

    echo -n "${ALL_SERVICES[@]}" > "$HOME/.seedbox_files"

    ###################################### TRAEFIK RULES ######################################

    # Skip this part for services which have Traefik rules disabled in config
    traefikEnabled=$(jq -r .traefik.enabled <<< "$json")
    if [[ ${traefikEnabled} == "false" ]]; then
        echo-debug "Traefik is disabled. Skipping rules creation..."
        continue
    fi

    # Loop over all Traefik rules and create the corresponding entries in the generated rules.yaml
    echo-debug "Generating Traefik rules..."
    TRAEFIK_RULES_INDEX=0
    RULES_PROPS_FILE="$TMP_FOLDER/rules.props"
    while read -r rule; do
        host=$(jq -r .host <<< "$rule")
        internalPort=$(jq -r .internalPort <<< "$rule")
        httpAuth=$(jq -r .httpAuth <<< "$rule")
        sso=$(jq -r .sso <<< "$rule")
        
        backendHost=${name}
        internalScheme="http"
        customInternalScheme=$(jq -r .internalScheme <<< "$rule")

        if [[ ${vpn} == "true" ]]; then
            backendHost="gluetun"
        fi
        if [[ ${customInternalScheme} != "null" ]]; then
            internalScheme=${customInternalScheme}
        fi

        # Transform the bash syntax into Traefik/go one => anything.${TRAEFIK_DOMAIN} to anything.{{ env "TRAEFIK_DOMAIN" }}
        prefix="${host%.\$\{*}"
        # shellcheck disable=SC2089
        hostTraefik="${prefix}.{{ env \"TRAEFIK_DOMAIN\" }}"

        ruleId="${name}-$((++TRAEFIK_RULES_INDEX))"
        echo "http.routers.${ruleId}.rule: Host(\`${hostTraefik}\`)" >> "$RULES_PROPS_FILE"

        middlewareCount=0
        if [[ ${httpAuth} == "true" ]]; then
            echo "http.routers.${ruleId}.middlewares.$((middlewareCount++)): common-auth@file" >> "$RULES_PROPS_FILE"
        fi
        if [[ ${sso} == "true" ]]; then
            echo "http.routers.${ruleId}.middlewares.$((middlewareCount++)): chain-authelia@file" >> "$RULES_PROPS_FILE"
        fi

        traefikService=$(jq -r .service <<< "$rule")
        if [[ ${traefikService} != "null" ]]; then
            echo "http.routers.${ruleId}.service: ${traefikService}" >> "$RULES_PROPS_FILE"
        else
            echo "http.routers.${ruleId}.service: ${ruleId}" >> "$RULES_PROPS_FILE"
        fi

        # Check if httpOnly flag is enabled
        # If enabled => Specify to use only "insecure" (port 80) entrypoint
        # If not => use all entryPoints (by not specifying any) but force redirection to https
        httpOnly=$(jq -r .httpOnly <<< "$rule")
        if [[ ${httpOnly} == true ]]; then
            echo "http.routers.${ruleId}.entryPoints.0: insecure" >> "$RULES_PROPS_FILE"
        else
            echo "http.routers.${ruleId}.tls.certresolver: le" >> "$RULES_PROPS_FILE"
            echo "http.routers.${ruleId}.middlewares.$((middlewareCount++)): redirect-to-https" >> "$RULES_PROPS_FILE"
        fi

        # If the specified service does not contain a "@" => we create it
        # If the service has a @, it means it is defined elsewhere so we do not create it (custom file, @internal...)
        if grep -vq "@" <<< "${traefikService}"; then
            echo "http.services.${ruleId}.loadBalancer.servers.0.url: ${internalScheme}://${backendHost}:${internalPort}" >> "$RULES_PROPS_FILE"
        fi
    done < <(jq -c '.traefik.rules[]' <<< "$json")
done < <(jq -c '.services[]' "$CONFIG_JSON_FILE")

###############################################################################################
####################################### TRAEFIK ###############################################
###############################################################################################

## Traefik Certificate Resolver tweaks
if [[ ! -z ${TRAEFIK_CUSTOM_ACME_RESOLVER} ]]; then
    if [[ ${TRAEFIK_CUSTOM_ACME_RESOLVER} == "changeme" ]]; then
        fatal "Wrong value for TRAEFIK_CUSTOM_ACME_RESOLVER variable."
    fi

    yq 'del(.certificatesResolvers.le.acme.httpChallenge)' -i traefik/traefik.yaml
    yq "(.certificatesResolvers.le.acme.dnsChallenge.provider=\"$TRAEFIK_CUSTOM_ACME_RESOLVER\")" -i traefik/traefik.yaml
fi

echo -n "${HTTP_USER}:${HTTP_PASSWORD}" > traefik/http_auth
yq -p=props "$RULES_PROPS_FILE" -o yaml > traefik/custom/dynamic-rules.yaml

###############################################################################################
####################################### DOCKER ################################################
###############################################################################################

# shellcheck disable=SC2068
docker compose ${ALL_SERVICES[@]} config -q

if [[ "${SKIP_PULL}" != "1" ]]; then
    echo "***** Pulling all images... *****"
    # shellcheck disable=SC2068
    docker compose ${ALL_SERVICES[@]} pull
fi

echo "***** Recreating containers if required... *****"
# shellcheck disable=SC2068
docker compose --env-file .env ${ALL_SERVICES[@]} up -d --remove-orphans

docker image prune -af &>/dev/null & disown
docker volume prune -f &>/dev/null & disown

echo "[$0] ***** Done! *****"
exit 0