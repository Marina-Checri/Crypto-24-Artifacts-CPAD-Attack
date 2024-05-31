# Use the official Ubuntu 22.04 base image
FROM ubuntu:22.04

# Set the timezone to Europe/Paris
ENV TZ=Europe/Paris

# Set the working directory inside the container
WORKDIR /usr/src/app

# Install necessary dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    g++ \
    make \
    time \
    libboost-all-dev

# Clone the OpenFHE official repository
#RUN git clone https://github.com/openfheorg/openfhe-development.git
# Copy the OpenFHE library directory into the container  (from version 1.1.4)
COPY "modified_openfhe" /usr/src/app/modified_openFHE

# Build and install OpenFHE
WORKDIR /usr/src/app/modified_openFHE
RUN mkdir build && cd build && cmake .. && make && make install

# Set the LD_LIBRARY_PATH environment variable
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# Command to run the compiled binary (replace 'your_binary_name' with the actual binary name)
ENV TERM xterm-256color
RUN echo 'export PS1="\[\e[36m\](docker@\h) \[\e[1;33m\][\[\e[38;5;130m\]\$(date +%H:%M:%S)\[\e[38;5;167m\] \u:\[\e[38;5;228m\] \w\[\e[1;33m\]]\[\e[m\]\n$ "' > /root/.bashrc

WORKDIR /attack_threshold_OpenFHE
# Copy the project files into the container
COPY . .

CMD ["bash", "-l"] 
