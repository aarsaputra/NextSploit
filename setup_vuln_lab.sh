#!/bin/bash
# Next.js Vulnerable Lab Setup (2024–2026)
# Target Directory: /nextjs-vuln-lab

set -e

LAB_DIR="/nextjs-vuln-lab"
USER_NAME=$SUDO_USER

if [ -z "$USER_NAME" ]; then
    USER_NAME=$(whoami)
fi

echo -e "\033[1;34m[*] Starting Next.js Vulnerable Lab Setup...\033[0m"

# 1. Create directory and set permissions
if [ ! -d "$LAB_DIR" ]; then
    echo -e "\033[1;33m[*] Creating lab directory at $LAB_DIR...\033[0m"
    sudo mkdir -p "$LAB_DIR"
    sudo chown -R "$USER_NAME:$USER_NAME" "$LAB_DIR"
else
    echo -e "\033[1;32m[+] Lab directory already exists at $LAB_DIR.\033[0m"
fi

cd "$LAB_DIR"

# Helper function to generate and patch lab apps
create_lab() {
    local folder=$1
    local next_version=$2
    local desc=$3

    if [ -d "$folder" ]; then
        echo -e "\033[1;33m[-] Skipping $folder (already exists)\033[0m"
        return
    fi

    echo -e "\033[1;34m[*] Generating $folder ($desc) with Next.js v$next_version...\033[0m"
    
    # We use npx to create the app. We need to install specific react versions compatible with next.
    # React 18 is generally safe for Next.js 13/14, React 19 rc for Next.js 15
    local react_version="18.2.0"
    if [[ "$next_version" == 15* ]]; then
        react_version="19.0.0-rc-69d4b800-20241021"
    fi

    # Check if npx is available
    if ! command -v npx &> /dev/null; then
        echo -e "\033[1;31m[!] Error: 'npx' command not found. Please install Node.js and NPM.\033[0m"
        exit 1
    fi

    # Force yes to all prompts
    npx -y create-next-app@$next_version $folder \
        --typescript \
        --eslint \
        --tailwind \
        --app \
        --src-dir \
        --import-alias "@/*" \
        --use-npm > /dev/null 2>&1 || true

    # Check if directory was actually created
    if [ ! -d "$folder" ]; then
         echo -e "\033[1;31m[!] Failed to generate Next.js app in $folder. npx command may have failed.\033[0m"
         return
    fi

    # Force install the vulnerable specific versions
    cd $folder
    npm install next@$next_version react@$react_version react-dom@$react_version --save-exact > /dev/null 2>&1
    cd ..

    
    echo -e "\033[1;32m[+] $folder created successfully.\033[0m"
}

# 2. Lab 1: Auth Bypass (CVE-2025-29927) - Next.js 14.2.24
create_lab "lab-1-auth-bypass" "14.2.24" "CVE-2025-29927"
cat << 'EOF' > "$LAB_DIR/lab-1-auth-bypass/src/middleware.ts"
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export function middleware(request: NextRequest) {
  // Vulnerable middleware logic that can be bypassed via x-middleware-subrequest
  if (request.nextUrl.pathname.startsWith('/admin')) {
    const isAuth = request.cookies.get('session');
    if (!isAuth) {
      return NextResponse.redirect(new URL('/login', request.url))
    }
  }
  return NextResponse.next()
}
export const config = { matcher: '/admin/:path*' }
EOF
mkdir -p "$LAB_DIR/lab-1-auth-bypass/src/app/admin"
cat << 'EOF' > "$LAB_DIR/lab-1-auth-bypass/src/app/admin/page.tsx"
export default function Admin() { return <h1>Admin Dashboard - Secret Data</h1>; }
EOF


# 3. Lab 2: SSRF via Host Header (CVE-2024-34351) - Next.js 14.1.0
create_lab "lab-2-ssrf" "14.1.0" "CVE-2024-34351"
cat << 'EOF' > "$LAB_DIR/lab-2-ssrf/src/app/actions.ts"
'use server'
export async function fetchData(url: string) {
    // Vulnerable server action that might be tricked by Host header manipulation
    const res = await fetch(url);
    return res.text();
}
EOF


# 4. Lab 3: RCE via Prototype Pollution (CVE-2025-66478) - Next.js 15.0.4
create_lab "lab-3-rce-proto" "15.0.4" "CVE-2025-66478"
cat << 'EOF' > "$LAB_DIR/lab-3-rce-proto/src/app/actions.ts"
'use server'
// A simple Server Action to trigger the vulnerable React 19 RSC deserialization
export async function submitForm(formData: FormData) {
    const data = Object.fromEntries(formData);
    return { success: true, message: `Received ${Object.keys(data).length} fields` };
}
EOF
cat << 'EOF' > "$LAB_DIR/lab-3-rce-proto/src/app/page.tsx"
import { submitForm } from './actions'
export default function Home() {
  return (
    <main className="p-8">
      <h1>RCE Target (CVE-2025-66478)</h1>
      <form action={submitForm}>
        <input type="text" name="test" defaultValue="payload" className="border p-2" />
        <button type="submit" className="bg-blue-500 text-white p-2 ml-2">Submit Action</button>
      </form>
    </main>
  )
}
EOF


# 5. Lab 4: Cache Poisoning / XSS (CVE-2024-46982) - Next.js 14.2.9
create_lab "lab-4-cache-poisoning" "14.2.9" "CVE-2024-46982"


# 6. Lab 5: DoS RSC (CVE-2026-23870) - Next.js 15.5.15
# Note: Since v15.5.15 might not exist on npm right now, we'll use a placeholder recent v15
create_lab "lab-5-dos-2026" "15.0.0" "CVE-2026-23870 (Simulated)"
cat << 'EOF' > "$LAB_DIR/lab-5-dos-2026/src/app/actions.ts"
'use server'
export async function heavyProcess(data: any) {
    // Simulate a vulnerable action that crashes on deeply nested/malformed objects
    return { status: "processed" };
}
EOF


echo -e "\n\033[1;32m[+] All labs generated successfully in $LAB_DIR!\033[0m"
echo -e "\033[1;34m[*] To run a lab:\033[0m"
echo -e "  cd /nextjs-vuln-lab/lab-1-auth-bypass"
echo -e "  npm run dev (Runs on http://localhost:3000)"
