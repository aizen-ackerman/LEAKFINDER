#!/bin/bash

echo "Compiling Java files..."
javac *.java

if [ $? -eq 0 ]; then
    echo "Compilation successful!"
    echo ""
    echo "Starting API Server..."
    echo "Open http://localhost:8080 in your browser"
    echo ""
    java ApiServer
else
    echo "Compilation failed. Please check for errors."
    exit 1
fi
