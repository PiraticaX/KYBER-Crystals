# Start from Python base
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    cmake ninja-build git build-essential libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt

# Build liboqs (C library)
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && mkdir build && cd build && \
    cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local .. && \
    ninja && ninja install

# Build liboqs-python bindings
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python.git && \
    cd liboqs-python && pip install cffi && pip install .

# App setup
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && pip install -r /app/requirements.txt
COPY . /app

EXPOSE 8080
CMD ["python3", "app.py"]