#!/bin/bash
# Intentional: AI in CI/CD — scripts that consume model output as shell
# commands, modify configs based on AI suggestions, and auto-deploy
# without human review.
#
# These represent build scripts, deployment helpers, and CI utilities that
# pipe AI/LLM output directly into shell execution. Often found as
# Makefile targets, CI helper scripts, or developer tooling.
#
# Scanner should flag: curl-to-eval patterns with AI output, model output
# in shell expansion, unsanitized AI responses used as commands.

set -e

# --- AI-powered deployment script ---

deploy_with_ai_review() {
    # Intentional: sends the entire git diff (which may contain secrets)
    # to an external AI API, then uses the AI's response to decide
    # whether to deploy and WHAT to deploy
    local DIFF
    DIFF=$(git diff HEAD~1 HEAD)

    local AI_VERDICT
    AI_VERDICT=$(curl -s https://api.openai.com/v1/chat/completions \
        -H "Authorization: Bearer $OPENAI_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{
            \"model\": \"gpt-4\",
            \"messages\": [{
                \"role\": \"user\",
                \"content\": \"Review this diff and output DEPLOY if safe, ROLLBACK if not, or a bash command to fix issues before deploy:\\n$DIFF\"
            }]
        }" | jq -r '.choices[0].message.content')

    # Intentional: if AI returns a command instead of DEPLOY/ROLLBACK,
    # it gets executed with full shell access
    if [ "$AI_VERDICT" = "DEPLOY" ]; then
        kubectl apply -f k8s/
    elif [ "$AI_VERDICT" = "ROLLBACK" ]; then
        kubectl rollout undo deployment/app
    else
        # Intentional: "fix command" from AI executed directly
        echo "AI suggested fix: $AI_VERDICT"
        eval "$AI_VERDICT"
    fi
}


# --- AI-powered Makefile-style build helper ---

ai_generate_build_config() {
    # Intentional: AI generates a Makefile that is then executed.
    # If the model is poisoned or prompt-injected, the Makefile
    # can contain arbitrary shell commands.
    local PROJECT_FILES
    PROJECT_FILES=$(find . -name '*.py' -o -name '*.js' | head -20 | xargs cat)

    curl -s https://api.openai.com/v1/chat/completions \
        -H "Authorization: Bearer $OPENAI_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{
            \"model\": \"gpt-4\",
            \"messages\": [{
                \"role\": \"user\",
                \"content\": \"Generate a Makefile for this project. Output ONLY the Makefile content:\\n$PROJECT_FILES\"
            }]
        }" | jq -r '.choices[0].message.content' > Makefile.ai

    # Intentional: AI-generated Makefile executed without review
    make -f Makefile.ai build
}


# --- AI-powered secret rotation ---

ai_rotate_secrets() {
    # Intentional: sends current secrets to AI and asks for new ones.
    # The AI sees all current secret values. Also, AI-generated
    # "random" secrets are not cryptographically random.
    local CURRENT_SECRETS
    CURRENT_SECRETS=$(cat .env)

    local NEW_SECRETS
    NEW_SECRETS=$(curl -s https://api.openai.com/v1/chat/completions \
        -H "Authorization: Bearer $OPENAI_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{
            \"model\": \"gpt-4\",
            \"messages\": [{
                \"role\": \"user\",
                \"content\": \"Generate new secret values for these environment variables. Keep the same keys, generate new strong random values. Output in .env format:\\n$CURRENT_SECRETS\"
            }]
        }" | jq -r '.choices[0].message.content')

    # Intentional: AI-generated secrets written directly to .env
    # and deployed. AI "random" values are deterministic and predictable.
    echo "$NEW_SECRETS" > .env
    source .env
    echo "Secrets rotated via AI"
}


# --- AI-powered database migration generator ---

ai_generate_migration() {
    # Intentional: AI generates SQL migration scripts that are
    # executed directly against the production database
    local SCHEMA
    SCHEMA=$(pg_dump --schema-only "$DATABASE_URL")

    local MIGRATION
    MIGRATION=$(curl -s https://api.openai.com/v1/chat/completions \
        -H "Authorization: Bearer $OPENAI_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{
            \"model\": \"gpt-4\",
            \"messages\": [{
                \"role\": \"user\",
                \"content\": \"Generate a SQL migration to add user analytics tables. Current schema:\\n$SCHEMA\\nOutput ONLY valid SQL.\"
            }]
        }" | jq -r '.choices[0].message.content')

    # Intentional: AI-generated SQL executed directly on production DB
    echo "$MIGRATION" | psql "$DATABASE_URL"
}


# --- AI-powered nginx config generator ---

ai_configure_nginx() {
    # Intentional: AI generates nginx configuration including
    # proxy_pass directives. A compromised model could redirect
    # traffic to attacker-controlled servers.
    local SERVICES
    SERVICES=$(docker ps --format '{{.Names}} {{.Ports}}')

    local NGINX_CONF
    NGINX_CONF=$(curl -s https://api.openai.com/v1/chat/completions \
        -H "Authorization: Bearer $OPENAI_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{
            \"model\": \"gpt-4\",
            \"messages\": [{
                \"role\": \"user\",
                \"content\": \"Generate an nginx.conf for reverse proxying these services:\\n$SERVICES\\nOutput ONLY valid nginx config.\"
            }]
        }" | jq -r '.choices[0].message.content')

    # Intentional: AI-generated nginx config deployed directly
    echo "$NGINX_CONF" > /etc/nginx/nginx.conf
    nginx -s reload
}


# --- AI-powered Dockerfile generator ---

ai_generate_dockerfile() {
    # Intentional: AI generates a Dockerfile that is then built.
    # Malicious model output could add RUN curl | bash steps,
    # expose ports, or install backdoored packages.
    local APP_CODE
    APP_CODE=$(cat app.py requirements.txt 2>/dev/null)

    local DOCKERFILE
    DOCKERFILE=$(curl -s https://api.openai.com/v1/chat/completions \
        -H "Authorization: Bearer $OPENAI_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{
            \"model\": \"gpt-4\",
            \"messages\": [{
                \"role\": \"user\",
                \"content\": \"Generate a production Dockerfile for this Python app:\\n$APP_CODE\"
            }]
        }" | jq -r '.choices[0].message.content')

    # Intentional: AI-generated Dockerfile built and pushed to registry
    echo "$DOCKERFILE" > Dockerfile.ai
    docker build -f Dockerfile.ai -t "$REGISTRY/app:latest" .
    docker push "$REGISTRY/app:latest"
}
