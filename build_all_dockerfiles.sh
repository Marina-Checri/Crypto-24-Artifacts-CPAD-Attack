#!/bin/bash

# Define colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
print_color() {
    color=$1
    message=$2
    echo -e "${color}${message}${NC}"
}

# Function to build Docker image with detailed output
build_docker_image() {
    repository=$1
    print_color $YELLOW "Building image from Dockerfile in $repository"
    print_color $YELLOW "--------------------------------------------------"

    # Display the Docker build command
    print_color $YELLOW "Running command: sudo docker buildx build -t ${repository,,}:0.1 ."

    # Build Docker image and show detailed output
    sudo docker buildx build -t "${repository,,}:0.1" .

    # Check if the build was successful
    if [ $? -eq 0 ]; then
        print_color $GREEN "Finished building Dockerfile in $repository"
    else
        print_color $RED "Error: Failed to build Dockerfile in $repository"
        exit 1
    fi

    print_color $YELLOW "--------------------------------------------------"
    echo
}

# Define an array of directories containing Dockerfiles
declare -a directories=(
    "attack_single-party/attack_lattigo"
    "attack_single-party/attack_OpenFHE"
    "attack_single-party/attack_regev"
    "attack_single-party/attack_SEAL"
    "attack_single-party/attack_tfheLib"
    "attack_multi-party/attack_threshold_OpenFHE"
    "attack_multi-party/attack_threshold_lattigo"
)

# Loop through each directory and build the Dockerfile
for dir in "${directories[@]}"
do
    # Navigate to the directory containing the Dockerfile
    cd "$dir" || { print_color $RED "Error: Could not change to directory $dir"; exit 1; }

    # Extract the repository name from the directory path
    repository=$(basename "$dir")

    # Build Docker image with detailed output
    build_docker_image "$repository"

    # Return to the original directory
    cd - > /dev/null
done

print_color $GREEN "All Docker images built successfully."
