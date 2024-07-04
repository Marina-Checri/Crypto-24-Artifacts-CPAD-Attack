# Use Ubuntu 22.04 as the base image
FROM ubuntu:22.04

# Set the timezone to Europe/Paris
ENV TZ=Europe/Paris

# Install Go
RUN apt-get update && apt-get install -y \
    wget \
    build-essential

RUN wget https://golang.org/dl/go1.18.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.18.linux-amd64.tar.gz
ENV PATH=$PATH:/usr/local/go/bin

# Set the working directory inside the container
WORKDIR /usr/src/app

# Install necessary dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libgmp-dev \
    libboost-program-options-dev \
    libssl-dev \
    time

# Clone the Lattigo repository from GitHub (version 5.0.2 of Lattigo)
#RUN git clone https://github.com/tuneinsight/lattigo.git
RUN git clone --branch v5.0.2 https://github.com/tuneinsight/lattigo.git

# Build Lattigo
WORKDIR /usr/src/app/lattigo
RUN make

# Command to run the compiled binary (replace 'your_binary_name' with the actual binary name)
ENV TERM xterm-256color
RUN echo 'export PS1="\[\e[36m\](docker@\h) \[\e[1;33m\][\[\e[38;5;130m\]\$(date +%H:%M:%S)\[\e[38;5;167m\] \u:\[\e[38;5;228m\] \w\[\e[1;33m\]]\[\e[m\]\n$ "' > /root/.bashrc

WORKDIR /attack_Lattigo
# Copy the project files into the container
COPY . .

RUN go mod init attack_lattigo
RUN go mod tidy

# Build your Go files
RUN go build -o code/src/bfv_attack code/src/bfv_attack.go

CMD ["bash", "-l"] 
