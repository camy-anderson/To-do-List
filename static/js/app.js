document.addEventListener("DOMContentLoaded", () => {
    const dateElement = document.getElementById("current-date");

    if (dateElement) {
        const now = new Date();

        dateElement.textContent = now.toLocaleDateString(
            undefined,
            {
                month: "short",
                day: "numeric",
                year: "numeric"
            }
        );
    }

    const flashMessages = document.querySelectorAll(".flash");

    flashMessages.forEach((message) => {
        setTimeout(() => {
            message.style.opacity = "0";
            message.style.transform = "translateY(-5px)";

            setTimeout(() => {
                message.remove();
            }, 250);
        }, 4500);
    });
});


function confirmDelete() {
    return window.confirm(
        "Are you sure you want to delete this task?"
    );
}
