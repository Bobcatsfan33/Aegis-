# ── Aegis — Sandbox VM for live remediation testing ─────────────────────
#
#  Why a VM and not just Docker?
#  The remediation agents use iptables, pkill, raw sockets, and nmap. These
#  require elevated privileges that — even with Docker caps — can still affect
#  your host machine's network or processes. A VM provides a hard boundary:
#  if an agent misfires or a scan target fights back, the blast radius is
#  limited to this throwaway VM.
#
#  Requirements:
#    vagrant     https://www.vagrantup.com/downloads
#    VirtualBox  https://www.virtualbox.org/  (free, cross-platform)
#    OR VMware   vagrant plugin install vagrant-vmware-desktop
#
#  Usage:
#    vagrant up                # boot + provision (first time ~5 min)
#    vagrant ssh               # SSH into the VM
#    vagrant halt              # pause without destroying
#    vagrant destroy           # wipe completely — safe to re-provision from scratch
#    vagrant snapshot save baseline   # snapshot before a destructive test
#    vagrant snapshot restore baseline
#
#  Inside the VM the project is mounted at /aegis
#  The API is forwarded to http://localhost:8000 on your host.
# ─────────────────────────────────────────────────────────────────────────────

Vagrant.configure("2") do |config|

  # Ubuntu 22.04 LTS — same base as the Docker runtime image
  config.vm.box = "ubuntu/jammy64"
  config.vm.box_check_update = false

  config.vm.hostname = "aegis-sandbox"

  # Forward the API port to your host machine
  config.vm.network "forwarded_port", guest: 8000,  host: 8000,  auto_correct: true
  # OpenSearch (optional — only if you're running the full stack inside the VM)
  config.vm.network "forwarded_port", guest: 9200,  host: 9200,  auto_correct: true
  # OpenSearch Dashboards
  config.vm.network "forwarded_port", guest: 5601,  host: 5601,  auto_correct: true

  # Private network so the VM can be scanned by network_agent tests
  config.vm.network "private_network", ip: "192.168.56.10"

  # Mount the project root into the VM (two-way sync)
  config.vm.synced_folder ".", "/aegis", type: "virtualbox"

  # ── VM resources ────────────────────────────────────────────────────────────
  config.vm.provider "virtualbox" do |vb|
    vb.name   = "aegis-sandbox"
    vb.memory = "2048"
    vb.cpus   = 2
    # Allow promiscuous mode so nmap can see all traffic on the private net
    vb.customize ["modifyvm", :id, "--nicpromisc2", "allow-all"]
  end

  # ── Provision: install everything needed to run Aegis ─────────────────
  config.vm.provision "shell", inline: <<-SHELL
    set -euo pipefail
    echo ">>> Updating apt"
    apt-get update -q

    echo ">>> Installing system packages"
    apt-get install -y -q \
      python3 python3-pip python3-venv \
      nmap \
      iptables \
      net-tools \
      curl \
      docker.io \
      docker-compose-v2

    # Add vagrant user to docker group
    usermod -aG docker vagrant

    echo ">>> Installing Python dependencies"
    cd /aegis
    pip3 install -r requirements.txt --break-system-packages -q

    echo ">>> Provisioning complete."
    echo "    cd /aegis && uvicorn api:app --host 0.0.0.0 --port 8000"
  SHELL

  # ── Post-provision message ───────────────────────────────────────────────────
  config.vm.post_up_message = <<-MSG

  ┌─────────────────────────────────────────────────────────┐
  │           Aegis Sandbox VM is ready               │
  ├─────────────────────────────────────────────────────────┤
  │  SSH in:     vagrant ssh                                │
  │  Project:    cd /aegis                            │
  │                                                         │
  │  Start API:  uvicorn api:app --host 0.0.0.0 --port 8000 │
  │  Full stack: docker compose up -d                       │
  │                                                         │
  │  API:        http://localhost:8000                      │
  │  Dashboards: http://localhost:5601                      │
  │                                                         │
  │  Snapshot before destructive tests:                     │
  │    vagrant snapshot save baseline                       │
  │    vagrant snapshot restore baseline                    │
  └─────────────────────────────────────────────────────────┘

  MSG

end
