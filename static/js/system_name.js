// system_name.js
window.addEventListener('DOMContentLoaded', () => {
    const systemNameSpan = document.getElementById('system-name');
    
    // Use the navigator object to retrieve system information
    const systemName = `${navigator.platform} - ${navigator.userAgent}`;
    
    systemNameSpan.textContent = systemName;
});
