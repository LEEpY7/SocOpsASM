# tools/ — ASM 파이프라인 바이너리 디렉토리

이 디렉토리에 아래 8개 툴의 바이너리를 배치하면 파이프라인이 자동으로 우선 사용합니다.  
바이너리가 없으면 시스템 PATH에서 탐색합니다.

## 배치 파일 목록

| 파일명 | 툴 | 공식 다운로드 |
|--------|----|--------------|
| `amass` | OWASP Amass v4.x | https://github.com/owasp-amass/amass/releases |
| `subfinder` | ProjectDiscovery Subfinder | https://github.com/projectdiscovery/subfinder/releases |
| `dnsx` | ProjectDiscovery dnsx | https://github.com/projectdiscovery/dnsx/releases |
| `naabu` | ProjectDiscovery Naabu | https://github.com/projectdiscovery/naabu/releases |
| `masscan` | Masscan | https://github.com/robertdavidgraham/masscan/releases |
| `nmap` | Nmap | https://nmap.org/download |
| `httpx` | ProjectDiscovery httpx (**Go 바이너리**) | https://github.com/projectdiscovery/httpx/releases |
| `nuclei` | ProjectDiscovery Nuclei | https://github.com/projectdiscovery/nuclei/releases |

> ⚠️ **httpx 주의**: Python `httpx` 패키지와 이름이 같습니다.  
> 반드시 **ProjectDiscovery httpx** (Go 바이너리, ~30MB) 를 사용하세요.  
> `file tools/httpx` 명령으로 `ELF 64-bit` 또는 `Mach-O` 인지 확인하세요.

## Linux (amd64) 빠른 설치 예시

```bash
cd tools/

# Subfinder
curl -sL https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_amd64.zip -o subfinder.zip
unzip subfinder.zip subfinder && rm subfinder.zip

# dnsx
curl -sL https://github.com/projectdiscovery/dnsx/releases/latest/download/dnsx_linux_amd64.zip -o dnsx.zip
unzip dnsx.zip dnsx && rm dnsx.zip

# Naabu
curl -sL https://github.com/projectdiscovery/naabu/releases/latest/download/naabu_linux_amd64.zip -o naabu.zip
unzip naabu.zip naabu && rm naabu.zip

# httpx (ProjectDiscovery — Go 바이너리)
curl -sL https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_linux_amd64.zip -o httpx.zip
unzip httpx.zip httpx && rm httpx.zip

# Nuclei
curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip -o nuclei.zip
unzip nuclei.zip nuclei && rm nuclei.zip

# Amass
curl -sL https://github.com/owasp-amass/amass/releases/latest/download/amass_linux_amd64.zip -o amass.zip
unzip amass.zip '*/amass' -d . && mv amass_linux_amd64/amass . && rm -rf amass_linux_amd64 amass.zip

# Masscan (컴파일 필요 또는 패키지 복사)
# sudo apt-get install masscan && cp /usr/bin/masscan .

# Nmap (컴파일 필요 또는 패키지 복사)
# sudo apt-get install nmap && cp /usr/bin/nmap .

# 실행 권한 부여
chmod +x amass subfinder dnsx naabu masscan nmap httpx nuclei
```

## macOS (arm64/amd64) 예시

```bash
# Homebrew
brew install amass nmap masscan

# ProjectDiscovery 툴 (darwin_amd64 또는 darwin_arm64)
# https://github.com/projectdiscovery/httpx/releases 에서 darwin 버전 다운로드
```

## 툴 경로 우선순위 (asm-pipeline.js)

```
1순위: <project>/tools/<toolname>   ← 이 디렉토리
2순위: 시스템 PATH (which amass 등)
```

## .gitignore

바이너리 파일은 이미 `.gitignore`에서 제외되어 있습니다.  
각 환경에서 직접 다운로드하여 배치하세요.
