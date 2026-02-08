// Global Logout Guard
// Handles Auto-Logout on Tab Close (Idle Users)
// Prevents Logout on Valid Navigation (Links, Forms)

(function () {
    let isNavigating = false;
    const status = window.USER_STATUS || 'idle'; // Default to idle if not set

    // Navigation Guard
    window.markNavigation = function () {
        isNavigating = true;
        console.log('[LogoutGuard] Manual navigation marked.');
    };

    function setupNavigationGuard() {
        // Detect clicks on links
        document.addEventListener('click', (e) => {
            const link = e.target.closest('a');
            if (link && link.href && !link.href.startsWith('javascript:')) {
                // IGNORE DOWNLOADS
                // If it looks like a download or has 'download' attribute
                if (link.hasAttribute('download') ||
                    link.href.includes('export') ||
                    link.href.includes('.xlsx') ||
                    link.href.includes('.pdf') ||
                    link.href.includes('download')) {
                    console.log('[LogoutGuard] Download detected, ignoring navigation.');
                    return;
                }

                if (link.target === '_blank') {
                    // New tab, current page stays open -> Not navigating away
                    return;
                }

                // It's a real navigation
                isNavigating = true;
                console.log('[LogoutGuard] Navigation detected (Link).');
            }
        });

        // Detect form submissions
        document.addEventListener('submit', (e) => {
            const form = e.target;
            const action = form.action || '';

            // IGNORE DOWNLOADS
            if (action.includes('export') ||
                action.includes('download') ||
                action.includes('.xlsx')) {
                console.log('[LogoutGuard] Download detected (Form), ignoring navigation.');
                return;
            }

            if (form.target === '_blank') {
                return;
            }

            isNavigating = true;
            console.log('[LogoutGuard] Navigation detected (Form).');
        });
    }

    // Auto-Logout Beacon
    function setupAutoLogout() {
        window.addEventListener('pagehide', () => {
            // Only logout if:
            // 1. Status is IDLE
            // 2. We are NOT navigating to another page in the app
            if (status === 'idle' && !isNavigating) {
                console.log('[LogoutGuard] Tab closed & Idle. Sending logout beacon.');
                navigator.sendBeacon('/auth/logout');
            }
        });
    }

    // Init
    document.addEventListener('DOMContentLoaded', () => {
        setupNavigationGuard();
        setupAutoLogout();
    });

})();
