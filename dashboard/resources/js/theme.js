// Theme manager — ikuti OS, bisa di-override manual
function initTheme() {
    const saved = localStorage.getItem('theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const useDark = saved ? saved === 'dark' : prefersDark;
    if (!useDark) document.documentElement.classList.add('light');
    updateIcons(!useDark);
}

function toggleTheme() {
    const isLight = document.documentElement.classList.toggle('light');
    localStorage.setItem('theme', isLight ? 'light' : 'dark');
    updateIcons(isLight);
}

function updateIcons(isLight) {
    const sun  = document.getElementById('iconSun');
    const moon = document.getElementById('iconMoon');
    if (sun)  sun.style.display  = isLight ? 'block' : 'none';
    if (moon) moon.style.display = isLight ? 'none'  : 'block';
}

// Init on load
initTheme();

// Export untuk dipakai di blade
window.toggleTheme = toggleTheme;