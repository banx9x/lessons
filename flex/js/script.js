(function () {
    let btnCollapse = document.querySelector(".btn--collapse");
    let menu = document.querySelector(".nav .menu");
    let dropdown = document.querySelector(".dropdown");
    let toggle = false;

    btnCollapse.addEventListener("click", function () {
        toggle = !toggle;
        dropdown.style.height = toggle ? menu.scrollHeight + "px" : "";
    });

    window.addEventListener("resize", function () {
        if (!toggle) return;

        if (this.document.documentElement.clientWidth >= 992) {
            toggle = !toggle;
            dropdown.style.height = "";
        }
    });
})();
