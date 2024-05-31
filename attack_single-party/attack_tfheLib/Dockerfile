# Use the official ubuntu 22.04 image as the base image
FROM ubuntu:22.04

# Set the working directory inside the container
WORKDIR /usr/src/app

# Install dependencies needed for the tfhe library
RUN apt-get update && apt-get install -y \
    cmake \
    g++ \
    make \
    git \
    libfftw3-dev \
    libboost-all-dev \    
    time

# Clone the tfhe library from the official repository (version 1.1 of tfheLib)
RUN git clone https://github.com/tfhe/tfhe.git

# Build and install the tfhe library
WORKDIR /usr/src/app/tfhe
RUN mkdir build && cd build && cmake ../src -DENABLE_FFTW=on -DCMAKE_BUILD_TYPE=debug && make && make install

# Get the path where TFHE is installed
ENV TFHE_FOLDER_PATH=$(pwd)

# Navigate back to the project directory
WORKDIR /usr/src/app

# Command to run the compiled binary (replace 'your_binary_name' with the actual binary name)
ENV TERM xterm-256color
RUN echo 'export PS1="\[\e[36m\](docker@\h) \[\e[1;33m\][\[\e[38;5;130m\]\$(date +%H:%M:%S)\[\e[38;5;167m\] \u:\[\e[38;5;228m\] \w\[\e[1;33m\]]\[\e[m\]\n$ "' > /root/.bashrc

WORKDIR /attack_tfheLib
# Copy the project files into the container
COPY . .

# Run ldconfig with sudo
RUN /sbin/ldconfig -v

CMD ["bash", "-l"] 
