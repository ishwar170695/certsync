FROM node:22-bookworm

# Install basic tools, sudo, and OpenJDK 17
RUN apt-get update && apt-get install -y \
    curl unzip python3 build-essential sudo openjdk-17-jdk-headless \
    && echo "node ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/node \
    && chmod 0440 /etc/sudoers.d/node

# Switch to non-root user 'node'
USER node
WORKDIR /home/node

# Install Volta
RUN curl https://get.volta.sh | bash
ENV PATH="/home/node/.volta/bin:${PATH}"

# Install NVM
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash

WORKDIR /workspace
