# Use ubuntu 22.04 image as the base image
FROM ubuntu:22.04

# Set the timezone to Europe/Paris
ENV TZ=Europe/Paris

# Set the working directory inside the container
WORKDIR /usr/src/app

# Install dependencies needed for the SEAL library
RUN apt-get update && apt-get install -y \
    cmake \
    g++ \
    git \
    make \
    time

# Copy the SEAL library directory into the container (version 4.1.2 of SEAL)
#RUN git clone --branch v4.1.2 https://github.com/microsoft/SEAL.git
COPY modified_SEAL /usr/src/app/modified_SEAL

# Build the SEAL library
WORKDIR /usr/src/app/modified_SEAL
RUN cmake -S . -B build && cmake --build build && cmake --install build

# Command to run the compiled binary (replace 'your_binary_name' with the actual binary name)
ENV TERM xterm-256color
RUN echo 'export PS1="\[\e[36m\](docker@\h) \[\e[1;33m\][\[\e[38;5;130m\]\$(date +%H:%M:%S)\[\e[38;5;167m\] \u:\[\e[38;5;228m\] \w\[\e[1;33m\]]\[\e[m\]\n$ "' > /root/.bashrc

WORKDIR /attack_SEAL
# Copy the project files into the container
COPY . .

CMD ["bash", "-l"] 
