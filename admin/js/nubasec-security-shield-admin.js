(function () {
    'use strict';

    document.addEventListener('DOMContentLoaded', function () {
        const colorInputs = document.querySelectorAll('.nss-settings-form input[type="color"]');
        colorInputs.forEach(function (input) {
            input.addEventListener('input', function () {
                if (input.name === 'nss_brand_color_primary') {
                    document.querySelector('.nss-wrap')?.style.setProperty('--nss-primary', input.value);
                }
                if (input.name === 'nss_brand_color_secondary') {
                    document.querySelector('.nss-wrap')?.style.setProperty('--nss-secondary', input.value);
                }
            });
        });
    });
}());
