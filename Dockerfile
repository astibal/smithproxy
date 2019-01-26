# Use an official Python runtime as a parent image
FROM ubuntu:18.04

# Set the working directory to /app
WORKDIR /app

COPY build/smithproxy-0.8.3-Linux.deb /app
# Copy the current directory contents into the container at /app

RUN apt update && apt install -y \
wget \
python-pip 

RUN dpkg -i smithproxy-0.8.3-Linux.deb && apt install -f


# Define environment variable

# Run app.py when the container launches
CMD ["/bin/sh",]
