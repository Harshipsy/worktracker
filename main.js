document.addEventListener("DOMContentLoaded", () => {
    document.body.addEventListener("keydown", function(e) {
        if (e.target.classList.contains("one-line") && e.key === "Enter") {
            e.preventDefault();
            const parent = e.target.parentElement;

            const newInput = document.createElement("input");
            newInput.className = "form-control one-line mt-1";
            newInput.name = e.target.name;
            newInput.placeholder = e.target.placeholder;

            parent.appendChild(newInput);
            newInput.focus();
        }
    });
});
