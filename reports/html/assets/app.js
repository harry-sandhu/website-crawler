document.addEventListener("DOMContentLoaded", () => {

    // =====================================
    // Make issue cards collapsible
    // =====================================

    document.querySelectorAll(".issue h3").forEach(title => {

        title.style.cursor = "pointer";

        title.addEventListener("click", () => {

            const card = title.parentElement;

            card.classList.toggle("collapsed");

        });

    });

    // =====================================
    // Create Search Box
    // =====================================

    const search = document.createElement("input");

    search.type = "text";

    search.placeholder = "Search issues...";

    search.style.width = "100%";
    search.style.padding = "14px";
    search.style.marginBottom = "25px";
    search.style.fontSize = "16px";

    const container = document.querySelector(".container");

    container.insertBefore(
        search,
        container.children[5],
    );

    search.addEventListener("input", () => {

        const text = search.value.toLowerCase();

        document.querySelectorAll(".issue").forEach(issue => {

            issue.style.display = issue.innerText
                .toLowerCase()
                .includes(text)
                ? ""
                : "none";

        });

    });

    // =====================================
    // Severity Filter
    // =====================================

    const filter = document.createElement("select");

    filter.innerHTML = `
        <option value="">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
    `;

    filter.style.padding = "14px";
    filter.style.marginBottom = "25px";
    filter.style.marginLeft = "15px";

    search.after(filter);

    filter.addEventListener("change", () => {

        const value = filter.value;

        document.querySelectorAll(".issue").forEach(issue => {

            if (!value) {

                issue.style.display = "";

                return;

            }

            issue.style.display = issue.classList.contains(value)
                ? ""
                : "none";

        });

    });

    // =====================================
    // Expand / Collapse Buttons
    // =====================================

    const controls = document.createElement("div");

    controls.style.marginBottom = "25px";

    controls.innerHTML = `
        <button id="expandAll">Expand All</button>
        <button id="collapseAll">Collapse All</button>
    `;

    filter.after(controls);

    controls.querySelectorAll("button").forEach(button => {

        button.style.marginRight = "10px";
        button.style.padding = "10px 18px";
        button.style.cursor = "pointer";

    });

    document
        .getElementById("expandAll")
        .addEventListener("click", () => {

            document
                .querySelectorAll(".issue")
                .forEach(issue => {

                    issue.classList.remove("collapsed");

                });

        });

    document
        .getElementById("collapseAll")
        .addEventListener("click", () => {

            document
                .querySelectorAll(".issue")
                .forEach(issue => {

                    issue.classList.add("collapsed");

                });

        });

});