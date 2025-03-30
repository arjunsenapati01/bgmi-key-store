// Mobile Menu Functionality
document.addEventListener('DOMContentLoaded', function() {
    // Get the navbar toggler button and navbar collapse
    const navbarToggler = document.querySelector('.navbar-toggler');
    const navbarCollapse = document.getElementById('navbarNav');

    // Function to toggle mobile menu
    function toggleMobileMenu() {
        if (navbarCollapse.classList.contains('show')) {
            navbarCollapse.classList.remove('show');
        } else {
            navbarCollapse.classList.add('show');
        }
    }

    // Add click event listener to the toggler button
    if (navbarToggler) {
        navbarToggler.addEventListener('click', function(e) {
            e.preventDefault();
            toggleMobileMenu();
        });
    }

    // Close mobile menu when clicking outside
    document.addEventListener('click', function(e) {
        if (!navbarCollapse.contains(e.target) && 
            !e.target.closest('.navbar-toggler') && 
            navbarCollapse.classList.contains('show')) {
            navbarCollapse.classList.remove('show');
        }
    });
}); 