# Use the official Ubuntu 22.04 image
FROM ubuntu:22.04

# Set the timezone to Europe/Paris
ENV TZ=Europe/Paris

# Set the working directory inside the container
WORKDIR /usr/src/app

# Update the package index and install Python 3.10 and required dependencies
RUN apt-get update && \
    apt-get install -y python3.10 && \
    apt-get install -y python3-pip && \
    python3.10 -m pip install --upgrade pip && \
    apt-get clean \
    time

# Command to run the compiled binary (replace 'your_binary_name' with the actual binary name)
ENV TERM xterm-256color
RUN echo 'export PS1="\[\e[36m\](docker@\h) \[\e[1;33m\][\[\e[38;5;130m\]\$(date +%H:%M:%S)\[\e[38;5;167m\] \u:\[\e[38;5;228m\] \w\[\e[1;33m\]]\[\e[m\]\n$ "' > /root/.bashrc

WORKDIR /attack_regev
# Copy the project files into the container
COPY . .

CMD ["bash", "-l"] 
