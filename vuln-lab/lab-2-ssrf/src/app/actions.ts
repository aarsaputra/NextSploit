'use server'
export async function fetchData(url: string) {
    // Vulnerable server action that might be tricked by Host header manipulation
    const res = await fetch(url);
    return res.text();
}
