docker run -d \
    --name cyberGraph \
    --restart always \
    --publish=7474:7474 --publish=7687:7687 \
    --env NEO4J_AUTH=neo4j/password \
    --env NEO4J_PLUGINS='["apoc", "graph-data-science"]' \
    --env NEO4J_server_memory_pagecache_size=10G \
    --env NEO4J_server_memory_heap_max__size=30G \
    --env NEO4J_server_memory_heap_initial__size=30G \
    -e NEO4J_apoc_export_file_enabled=true \
    -e NEO4J_apoc_import_file_enabled=true \
    --mount type=bind,source="$(pwd)"/graph,target=/data \
    neo4j:2025.10.1
