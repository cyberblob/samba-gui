# Samba GUI — The Friendly Guide

So you want to share files between computers on your home or office network? That's exactly what Samba does, and this app gives you a nice graphical way to set it all up without memorizing terminal commands.

This guide assumes you've never done any of this before. We'll go step by step.

---

## What Even Is Samba?

Samba is the software that lets Linux computers share files and printers with other computers on your network — including Windows and Mac machines. It speaks the same "language" (SMB/CIFS protocol) that Windows uses for file sharing.

**Without Samba GUI**, you'd be editing cryptic config files by hand and running terminal commands to manage users and services.

**With Samba GUI**, you click buttons and fill in forms. Same result, less pain.

---

## What You Need Before Starting

### Hardware / OS

- A computer running **Linux** (Debian, Ubuntu, Linux Mint, Fedora, or Arch)
- An internet connection (to install packages)

### Skill Level

- You should know how to open a terminal (usually Ctrl+Alt+T)
- You should know your user password (the one you type to log in)

That's it. We'll walk you through everything else.

---

## Installing Samba GUI

### Option A: Install the .deb Package (Easiest — Debian/Ubuntu/Linux Mint)

If someone gave you a `.deb` file (like `samba-gui_0.1.10_amd64.deb`), just double-click it in your file manager. Your system's package installer will handle the rest.

Or from the terminal:

```bash
sudo apt install ./samba-gui_0.1.10_amd64.deb
```

**What does `sudo` mean?** It's how you tell Linux "I need admin powers for this command." It'll ask for your password.

Done. Skip to [Launching the App](#launching-the-app).

---

### Option B: Build It Yourself (For the Adventurous)

This takes more steps, but it's not scary. We'll install the tools, grab the code, and build it.

#### Step 1: Install System Packages

These are libraries the app needs to draw its window and buttons.

**Debian / Ubuntu / Linux Mint:**
```bash
sudo apt update
sudo apt install libgtk-4-dev libadwaita-1-dev samba samba-common-bin build-essential curl
```

**Fedora:**
```bash
sudo dnf install gtk4-devel libadwaita-devel samba samba-common-tools gcc curl
```

**Arch Linux:**
```bash
sudo pacman -S gtk4 libadwaita samba base-devel curl
```

#### Step 2: Install Rust

Rust is the programming language this app is written in. Installing it is one command:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

When it asks you questions, just press Enter to accept the defaults.

After it finishes, close your terminal and open a new one (so it picks up the new tools), or run:

```bash
source "$HOME/.cargo/env"
```

Verify it worked:

```bash
rustc --version
```

You should see something like `rustc 1.XX.X`. The exact number doesn't matter as long as it's recent.

#### Step 3: Build the App

Navigate to the project folder (wherever you downloaded or cloned it):

```bash
cd samba-gui
```

Build it with the graphical interface enabled:

```bash
cargo build --release --features gui
```

This will take a few minutes the first time — it's downloading and compiling all the pieces. Go grab a coffee.

#### Step 4: Run It

```bash
cargo run --release --features gui
```

Or run the compiled binary directly:

```bash
./target/release/samba-gui
```

---

## Launching the App

If you installed the `.deb` package, you can:

- Search for **"Samba GUI"** in your application menu (the same place you find Firefox, Files, etc.)
- Or run `samba-gui` from a terminal

The app will ask for your password once when it needs to do something that requires admin access (like changing Samba settings or managing users). After that first prompt, it remembers for the rest of the session. No repeated password popups.

---

## What Can You Do With It?

The app has a sidebar on the left with these sections:

### 1. Server Configuration

**What it does:** Controls how YOUR computer shares files with others.

Think of it like this: you have a folder on your computer, and you want your family/coworkers to be able to access it from their computers. This is where you set that up.

- **Global Settings** — General rules for all shares (security level, which SMB versions to allow, etc.)
- **Templates** — Pre-made configurations you can apply with one click. "Default (Secure)" is a good starting point. The app shows you exactly what will change before applying.

### 2. Client Configuration

**What it does:** Connects YOUR computer to shared folders on OTHER computers.

Say your NAS (network storage box) or a coworker's machine has a shared folder. This section helps you mount (connect to) that folder so it shows up like a regular folder on your computer.

It uses a step-by-step **Mount Wizard**:

1. **Pick how to log in** — Guest (no password), credentials file (username/password saved in a file), or Kerberos (corporate/Active Directory networks)
2. **Enter connection details** — The address of the share (like `//192.168.1.100/SharedDocs`) and where you want it to appear on your computer
3. **Set options** — Things like whether it should auto-connect at boot
4. **Validation** — The app checks if everything looks right before committing
5. **Confirm** — Review and apply

### 3. Service Management

**What it does:** Starts, stops, and restarts the Samba background services.

Samba runs as a "service" (a program that runs in the background). Sometimes you need to restart it after changing settings. This section gives you buttons for that instead of typing `systemctl` commands.

The services are:
- **smbd** — The main file sharing service
- **nmbd** — Helps other computers find your shares by name
- **winbind** — Used when your Linux machine is part of a Windows domain

### 4. User Management

**What it does:** Manages who can access your shared folders.

Samba has its own user database (separate from your Linux login users). You need to add users here before they can connect to your shares from other computers.

The app auto-detects whether you're running a simple standalone server or a full Active Directory Domain Controller, and shows the right tools for each.

### 5. Backup / Restore

**What it does:** Saves a copy of your current Samba configuration so you can go back to it if something breaks.

Always make a backup before making big changes. The backups are timestamped so you can tell them apart.

### 6. Firewall

**What it does:** Checks whether your firewall (ufw or firewalld) is blocking the ports Samba needs.

Samba uses ports 445, 139, 137, and 138. If your firewall is blocking them, other computers won't be able to reach your shares. This section shows you which ports are open and which are blocked, and has a button to open them all at once.

### 7. Network Discovery

**What it does:** Scans your local network for other computers that are sharing files via SMB.

Instead of guessing IP addresses, you can browse what's available on your network. The app uses Avahi (mDNS) and NetBIOS lookups to find hosts, then lets you list their shares. Handy when you want to connect to something but don't remember the exact address.

---

## Common Scenarios

### "I just want to share a folder with my home network"

1. Open Samba GUI
2. Go to **Server Configuration**
3. Apply the **"Simple File Server"** template
4. Go to **User Management** → add yourself as a Samba user (set a password — it can be different from your login password)
5. Go to **Service Management** → make sure `smbd` is running
6. On your other computer (Windows/Mac/Linux), open the file manager and connect to `\\YOUR-LINUX-IP\sharename`

### "I want to access a shared folder from another computer"

1. Open Samba GUI
2. Go to **Network Discovery** to scan for available hosts and shares on your network
3. Or go to **Client Configuration** directly if you already know the share address
4. Click the button to add a new mount
5. Follow the wizard — enter the share address (like `//192.168.1.50/Documents`), pick where to mount it, choose your auth method
6. Done — the folder appears at the mount point you chose

### "My computer is domain-joined and I want to use Kerberos mounts"

If your machine is part of a corporate Active Directory (AD) domain, you can mount network shares without storing passwords in files. Instead, you use Kerberos tickets — think of them as temporary "passes" that prove who you are.

Here's what you need before starting:

**Prerequisites (your sysadmin may have already done some of these):**

1. **Your machine must be joined to the domain.** You can check by running:
   ```bash
   realm list
   ```
   If it shows your domain (like `EXAMPLE.COM`), you're joined. If it shows nothing, you need to join first — that's outside the scope of this app.

2. **You need a keytab file.** A keytab is like a stored password that the system can use automatically (without you typing anything). It's usually at `/etc/krb5.keytab`. Ask your sysadmin if you don't have one.

3. **Your `/etc/krb5.conf` must be configured.** This file tells your computer where to find the Kerberos servers. On a domain-joined machine, this is usually already set up. It looks something like:
   ```ini
   [libdefaults]
       default_realm = EXAMPLE.COM
       dns_lookup_realm = true
       dns_lookup_kdc = true

   [realms]
       EXAMPLE.COM = {
           kdc = dc1.example.com
           admin_server = dc1.example.com
       }

   [domain_realm]
       .example.com = EXAMPLE.COM
       example.com = EXAMPLE.COM
   ```

4. **The share address must use a fully qualified domain name (FQDN).** Kerberos won't work with short names or IP addresses. Use `//fileserver.example.com/ShareName`, not `//fileserver/ShareName` or `//192.168.1.50/ShareName`.

5. **DNS must resolve the server name.** Test it:
   ```bash
   getent hosts fileserver.example.com
   ```
   If that returns an IP address, you're good.

6. **DNS SRV records should exist for Kerberos.** The app checks this automatically, but you can verify manually:
   ```bash
   dig +short SRV _kerberos._udp.example.com
   ```
   If that returns server entries, Kerberos auto-discovery works. If not, make sure your `/etc/krb5.conf` has the realm info hardcoded (see step 3).

**Setting up the mount in Samba GUI:**

1. Go to **Client Configuration** → add a new mount
2. In Step 1 (Auth Selection), choose **Kerberos**
3. In Step 2 (Connection Details), enter the share address using the FQDN: `//fileserver.example.com/ShareName`
4. In Step 3 (Mount Options), enable **Automount** if you want it available at boot
5. In Step 4 (Validation), the app will automatically check:
   - Is the hostname an FQDN? (must have a dot in it)
   - Can it resolve the hostname via DNS?
   - Are there Kerberos SRV records for the domain?
   - Do you have a valid Kerberos ticket right now?
6. In Step 5 (Summary), you'll see the units to be created — including `krb5-kinit.service`

**What is `krb5-kinit.service`?**

When you create a Kerberos mount, the app also creates a systemd service called `krb5-kinit.service`. This service runs automatically at boot (before your network drives are mounted) and obtains a fresh Kerberos ticket using your keytab. Without it, your Kerberos mounts would fail after a reboot because there'd be no valid ticket.

The service does the equivalent of:
```bash
kinit -k -t /etc/krb5.keytab yourprincipal@EXAMPLE.COM
```

It runs once at boot, gets the ticket, and then your mounts can authenticate.

**Troubleshooting Kerberos mounts:**

- **"FQDN required" error in validation** — You used a short hostname. Change `//server/share` to `//server.example.com/share`.
- **"No DNS SRV records found"** — Either your DNS isn't set up for Kerberos auto-discovery, or you're using the wrong domain. Check `/etc/krb5.conf`.
- **"No valid Kerberos ticket"** — Run `klist` in a terminal. If it says "No credentials cache found", try `kinit yourusername@EXAMPLE.COM` (note: realm is UPPERCASE). If that works, the mount should too.
- **Mount fails after reboot** — Check that `krb5-kinit.service` is enabled: `systemctl is-enabled krb5-kinit.service`. If it says "disabled" or "not-found", re-create the mount in Samba GUI.
- **"kinit: Client not found in Kerberos database"** — The principal (username@REALM) is wrong. Double-check with your sysadmin.
- **Ticket expires and mount stops working** — Kerberos tickets have a limited lifetime (usually 8-10 hours). For long-running mounts, your sysadmin should configure ticket renewal, or you can re-run `kinit` manually.

---

### "I changed settings and now nothing works"

1. Open Samba GUI
2. Go to **Backup / Restore**
3. Restore your most recent backup
4. Go to **Service Management** → restart `smbd`
5. Breathe

---

## Glossary (Jargon Decoder)

| Term | What It Actually Means |
|------|----------------------|
| **SMB / CIFS** | The protocol (language) computers use to share files over a network. SMB is the modern name, CIFS is the older name. Same thing. |
| **Share** | A folder you've made available to other computers on the network. |
| **Mount** | Making a remote folder appear as if it's a local folder on your computer. |
| **systemd** | The system that manages background services on modern Linux. Think of it as the "service manager." |
| **smb.conf** | The main Samba configuration file, lives at `/etc/samba/smb.conf`. This app edits it for you. |
| **testparm** | A Samba tool that checks if your config file is valid. The app uses it behind the scenes. |
| **sudo** | "Super User DO" — run a command with admin privileges. |
| **NAS** | Network Attached Storage — a dedicated box on your network for storing files. |
| **Kerberos** | An authentication system used in corporate/Active Directory networks. Uses "tickets" instead of sending passwords over the network. If you don't know what this is, you probably don't need it. |
| **Keytab** | A file (usually `/etc/krb5.keytab`) that stores a machine's Kerberos credentials so it can authenticate without a human typing a password. Used for boot-time ticket acquisition. |
| **Principal** | A Kerberos identity, written as `name@REALM` (e.g., `jsmith@EXAMPLE.COM`). The realm is always uppercase. |
| **krb5.conf** | The Kerberos configuration file at `/etc/krb5.conf`. Tells your computer which servers handle authentication for your domain. |
| **FQDN** | Fully Qualified Domain Name — the full name of a computer including its domain (e.g., `fileserver.example.com` not just `fileserver`). Kerberos requires these. |
| **Active Directory (AD)** | Microsoft's system for managing users and computers in a corporate network. |
| **Domain Controller (DC)** | The server that runs Active Directory. Samba can act as one. |
| **winbind** | A Samba service that integrates Linux with Windows domains. Home users can ignore this. |
| **nmbd** | NetBIOS name service — helps computers find each other by name instead of IP address. |
| **fstab** | An older way Linux connects to network drives at boot. This app uses the newer systemd method instead. |
| **.mount / .automount** | Systemd unit files that define network drive connections. The modern replacement for fstab entries. |
| **Avahi / mDNS** | A service that helps computers find each other on the local network without a central server. Used by the Network Discovery feature. |
| **nmblookup** | A Samba tool that finds computers on the network using NetBIOS names. Also used by Network Discovery. |

---

## Troubleshooting

### "The app won't start"

- Make sure you have GTK4 and libadwaita installed (see [Install System Packages](#step-1-install-system-packages))
- Try running from a terminal to see error messages: `samba-gui` or `cargo run --features gui`

### "It says permission denied"

- The app needs your password for admin operations. Make sure you're entering the correct login password when prompted.
- Your user account needs to be in the `sudo` group. On most desktop Linux installs, the first user account already is.

### "Other computers can't see my shares"

- Is `smbd` running? Check in **Service Management**.
- Is your firewall blocking Samba? Check in the **Firewall** section — it shows you which ports are open and which are blocked. Click "Open SMB Ports" to fix it automatically. Or manually:
  ```bash
  sudo ufw allow samba
  ```
- Are you on the same network? Both computers need to be on the same local network (same Wi-Fi, same router).

### "I can't connect to a remote share"

- Double-check the share address. It should look like `//192.168.1.100/ShareName` (forward slashes, not backslashes).
- Can you ping the other computer? Try `ping 192.168.1.100` from a terminal.
- Is the remote share actually shared and accessible? Test from another computer first if possible.
- Did you enter the right username and password for that share?

### "The mount disappears after reboot"

- Make sure you enabled the **automount** option in the Mount Wizard (Step 3: Mount Options).
- Check that the systemd mount service is enabled: go to **Client Configuration** and verify the mount shows as active.

---

## Uninstalling

If you installed via `.deb`:

```bash
sudo apt remove samba-gui
```

If you built it yourself, just delete the project folder. There's nothing else to clean up (the app doesn't install itself system-wide when you run it from the source folder).

---

## Getting Help

- Check the [main README](README.md) for technical details
- Look at the error messages in the terminal — they usually tell you exactly what's wrong
- When in doubt: make a backup, then experiment

---

## License

This software is free and open source, licensed under GPL-3.0. You can use it, modify it, and share it. See the [LICENSE](LICENSE) file for the legal text.
