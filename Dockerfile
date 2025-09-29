FROM kalilinux/kali-rolling:latest

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    build-essential \
    libssl-dev \
    libffi-dev \
    nmap \
    gobuster \
    nikto \
    metasploit-framework \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create Python virtual environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Install Python dependencies
RUN pip install --no-cache-dir mcp

# Copy application files
COPY pentest_mcp.py /app/
COPY tools/ /app/tools/

# Initialize Metasploit database (optional but recommended)
RUN msfdb init || true

# Set executable permissions
RUN chmod +x /app/pentest_mcp.py

# Run the MCP server
CMD ["python", "/app/pentest_mcp.py"]