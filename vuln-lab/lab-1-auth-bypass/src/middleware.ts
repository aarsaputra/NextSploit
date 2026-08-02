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
