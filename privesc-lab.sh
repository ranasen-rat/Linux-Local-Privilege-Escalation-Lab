#!/bin/bash

# Linux Privilege Escalation Lab - Complete Vulnerable Environment
# WARNING: This is for authorized pentesting/educational use only
# Author: Rana Sen

set -e

LAB_DIR="/opt/privesc-lab"
USER_HOME="/home/user"
TOOLS_DIR="$USER_HOME/tools"

echo "[+] Setting up Linux Privilege Escalation Lab..."
echo "[+] Lab directory: $LAB_DIR"
echo "[+] User home: $USER_HOME"

# Create lab structure
mkdir -p "$LAB_DIR" "$TOOLS_DIR/linux-exploit-suggester" "$TOOLS_DIR/dirtycow" \
         "$TOOLS_DIR/exim" "$USER_HOME/.config" /tmp/1

# Create user if needed
if ! id "user" &>/dev/null; then
    useradd -m -s /bin/bash user
    echo "user:password123" | chpasswd
    echo "user ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/lab-user
fi

cd /tmp

# ================================
# Exercise 1 - Dirty COW Kernel
# ================================
cat > dirtycow_setup.sh << 'EOF'
#!/bin/bash
# Vulnerable kernel setup (simulate old kernel)
echo "kernel.panic_on_oops = 1" >> /etc/sysctl.conf
sysctl kernel.panic_on_oops=1

cat > $TOOLS_DIR/dirtycow/c0w.c << 'COWC'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <sys/mman.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <target_file> <payload>\n", argv[0]);
        return 1;
    }
    
    int fd = open(argv[1], O_RDONLY);
    char *mem = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    
    // Dirty COW exploit payload
    char payload[] = "#!/bin/bash\nsetuid(0); setgid(0); /bin/bash -p\n";
    
    // Simulate dirtycow race condition
    printf("[+] Dirty COW exploiting %s...\n", argv[1]);
    sleep 2;
    
    FILE *f = fopen("/tmp/root_shell.sh", "w");
    fwrite(payload, 1, strlen(payload), f);
    fclose(f);
    chmod("/tmp/root_shell.sh", 0755);
    
    printf("[+] Root shell created at /tmp/root_shell.sh\n");
    printf("[+] Run: chmod +s /tmp/root_shell.sh && /tmp/root_shell.sh\n");
    return 0;
}
EOF

cat > $TOOLS_DIR/linux-exploit-suggester/linux-exploit-suggester.sh << 'EOF'
#!/bin/bash
echo "[+] Kernel: 3.13.0-32-generic (VULNERABLE)"
echo "[+] Potential exploits:"
echo "  dirtycow (CVE-2016-5195) - HIGH"
echo "  priv_esc (CVE-2017-16995) - MEDIUM"
echo ""
echo "Run: gcc -pthread $TOOLS_DIR/dirtycow/c0w.c -o c0w && ./c0w"
EOF

chmod +x dirtycow_setup.sh $TOOLS_DIR/linux-exploit-suggester/linux-exploit-suggester.sh
./dirtycow_setup.sh
rm dirtycow_setup.sh

# ================================
# Exercise 2 - Exim RCE
# ================================
cat > $TOOLS_DIR/exim/cve-2016-1531.sh << 'EOF'
#!/bin/bash
echo "[+] Exim 4.84 RCE (CVE-2016-1531)"
echo "[+] Triggering perl_startup RCE..."

# Simulate exim RCE
cat > /tmp/exim_payload << 'PAYLOAD'
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash");
PAYLOAD

echo "[+] Payload delivered. Check: /tmp/bash -p"
echo "[+] Current user: $(id)"
EOF

chmod +x $TOOLS_DIR/exim/cve-2016-1531.sh

# Create fake exim package
echo "ii  exim4-base  4.84-8ubuntu1  all  dummy exim package" > /tmp/exim_pkg.txt

cat > /etc/exim.conf << 'EOF'
perl_startup = do '/tmp/exim_payload'
daemon_smtp_port = 25
EOF

# ================================
# Exercise 3 - Memory Password Mining
# ================================
cat > /tmp/ftp_memory_setup.sh << 'EOF'
#!/bin/bash
cat >> /etc/passwd << 'EOF'
ftpuser:x:1001:1001:FTP User:/home/ftpuser:/bin/bash
EOF
echo "ftpuser:password321" | chpasswd
EOF
chmod +x /tmp/ftp_memory_setup.sh && /tmp/ftp_memory_setup.sh

# ================================
# Exercise 4 - Config File Passwords
# ================================
cat > $USER_HOME/myvpn.ovpn << 'EOF'
client
dev tun
proto udp
remote vpn.example.com 1194
auth-user-pass /etc/openvpn/auth.txt
EOF

echo "admin:supersecretpass" > /etc/openvpn/auth.txt
chmod 644 /etc/openvpn/auth.txt

cat >> $USER_HOME/.irssi/config << 'EOF'
passwords = { "irc.example.com" = "ircpass123"; };
EOF

# ================================
# Exercise 5 - Bash History
# ================================
echo "echo password321 > /tmp/creds.txt" >> $USER_HOME/.bash_history

# ================================
# Exercise 6-8 - Sudo Escapes
# ================================
cat >> /etc/sudoers.d/lab << 'EOF'
user ALL=(ALL) NOPASSWD: /bin/find, /usr/bin/awk, /usr/bin/nmap, /usr/bin/vim, /usr/sbin/apache2
user ALL=(ALL) NOPASSWD: SETENV: /usr/sbin/apache2
EOF

# ================================
# Exercise 9 - NFS no_root_squash
# ================================
mkdir -p /tmp/nfs_share
chown nobody:nogroup /tmp/nfs_share
chmod 777 /tmp/nfs_share

cat > /etc/exports << 'EOF'
/tmp/nfs_share *(rw,sync,no_subtree_check,no_root_squash,insecure)
EOF

exportfs -ra

# ================================
# Exercise 10-12 - Cron Jobs
# ================================
cat > /etc/crontab << 'EOF'
* * * * * root PATH=/home/user:$PATH /home/user/overwrite.sh
* * * * * root /usr/local/bin/compress.sh
EOF

mkdir -p /usr/local/bin
cat > /home/user/overwrite.sh << 'EOF'
#!/bin/bash
echo "Cron overwrite job running..."
EOF
chmod +x /home/user/overwrite.sh

cat > /usr/local/bin/compress.sh << 'EOF'
#!/bin/bash
tar czf /var/backups/home.tar.gz /home/user/ --checkpoint=1 --checkpoint-action=exec=sh /home/user/runme.sh
EOF
chmod +x /usr/local/bin/compress.sh

cat > /usr/local/bin/overwrite.sh << 'EOF'
#!/bin/bash
echo "File overwrite cron job"
EOF
chmod 777 /usr/local/bin/overwrite.sh

# ================================
# Exercise 13 - SUID .so Injection
# ================================
cat > /usr/local/bin/suid-so.c << 'EOF'
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>

int main() {
    printf("[+] Loading libcalc.so from ~/.config\n");
    void *handle = dlopen("/home/user/.config/libcalc.so", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "[-] Failed to load libcalc.so\n");
        return 1;
    }
    return 0;
}
EOF
gcc -o /usr/local/bin/suid-so /usr/local/bin/suid-so.c
chmod u+s /usr/local/bin/suid-so

# ================================
# Exercise 14 - Nginx Symlink (simplified)
# ================================
cat > /usr/local/bin/nginxed-root.sh << 'EOF'
#!/bin/bash
LOGFILE=$1
echo "[+] Nginx symlink exploit simulation"
echo "[+] Waiting for logrotate..."
sleep 3
echo "[+] Creating root shell"
/bin/bash -p
EOF
chmod +x /usr/local/bin/nginxed-root.sh

# ================================
# Exercise 15-16 - SUID Environment Variables
# ================================
cat > /usr/local/bin/suid-env.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    printf("[+] SUID-ENV: Calling 'service nginx restart'\n");
    char *args[] = {"service", "nginx", "restart", NULL};
    execve("/usr/sbin/service", args, NULL);
    return 0;
}
EOF

cat > /usr/local/bin/suid-env2.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    printf("[+] SUID-ENV2: Calling 'service nginx status'\n");
    char *args[] = {"service", "nginx", "status", NULL};
    execve("/usr/sbin/service", args, NULL);
    return 0;
}
EOF

gcc -o /usr/local/bin/suid-env /usr/local/bin/suid-env.c
gcc -o /usr/local/bin/suid-env2 /usr/local/bin/suid-env2.c
chmod u+s /usr/local/bin/suid-env /usr/local/bin/suid-env2

# Create fake service wrapper
cat > /usr/sbin/service << 'EOF'
#!/bin/bash
echo "Service command: $@"
EOF
chmod +x /usr/sbin/service

echo "[+] Lab setup complete!"
echo ""
echo "[+] Switch to user 'user' (password: password123)"
echo "[+] Run each exercise as instructed in the workshop guide"
echo "[+] All tools, files, and vulnerable services are in place"
echo ""
echo "[+] Quick test: sudo -l  (should show multiple sudo entries)"
echo "[+] Quick test: find / -perm -4000 2>/dev/null (should show SUID binaries)"
