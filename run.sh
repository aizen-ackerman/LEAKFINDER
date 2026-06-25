#!/bin/bash

# Build React frontend if present
if [ -d "frontend" ] && [ -f "frontend/package.json" ]; then
    echo "Building React frontend..."
    (cd frontend && npm run build)
    echo "Copying compiled assets to Spring Boot static resources..."
    mkdir -p src/main/resources/static
    rm -rf src/main/resources/static/assets
    cp -r frontend/dist/* src/main/resources/static/
fi

echo "Compiling Java files..."
javac -d . src/main/java/com/leakfinder/ApiServer.java src/main/java/com/leakfinder/VulnScanner.java

if [ $? -eq 0 ]; then
    echo "Compilation successful!"
    echo ""
    echo "Starting API Server..."
    echo "Open http://localhost:8080 in your browser"
    echo ""
    java com.leakfinder.ApiServer
else
    echo "Compilation failed. Please check for errors."
    exit 1
fi
