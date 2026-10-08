from .models import ResponsiveElement


def inspect_dom(page):
    data = page.evaluate("""
    () => {

        function buildSelector(el){

            if(el.id)
                return "#" + el.id;

            let selector = el.tagName.toLowerCase();

            if(el.classList.length){
                selector += "." + [...el.classList].slice(0,3).join(".");
            }

            return selector;
        }

        const elements = [];

        document.querySelectorAll("*").forEach(el => {

            const rect = el.getBoundingClientRect();
            const style = getComputedStyle(el);

            elements.push({

                // --------------------------------
                // Basic
                // --------------------------------

                tag: el.tagName,

                id: el.id || "",

                classes: (typeof el.className === "string" ? el.className : (el.getAttribute("class") || "")),

                selector: buildSelector(el),

                parent:
                    el.parentElement
                        ? el.parentElement.tagName
                        : "",

                text:
                    (el.innerText || "")
                        .trim()
                        .replace(/\\s+/g," ")
                        .slice(0,80),

                // --------------------------------
                // Position
                // --------------------------------

                x: rect.x,
                y: rect.y,

                width: rect.width,
                height: rect.height,

                top: rect.top,
                left: rect.left,
                right: rect.right,
                bottom: rect.bottom,

                // --------------------------------
                // Visibility
                // --------------------------------

                visible:
                    rect.width > 0 &&
                    rect.height > 0 &&
                    style.display !== "none" &&
                    style.visibility !== "hidden" &&
                    style.opacity !== "0",

                display: style.display,

                visibility: style.visibility,

                opacity: style.opacity,

                // --------------------------------
                // Positioning
                // --------------------------------

                position: style.position,

                fixed:
                    style.position === "fixed",

                sticky:
                    style.position === "sticky",

                z_index: style.zIndex,

                // --------------------------------
                // Overflow
                // --------------------------------

                overflow_x:
                    rect.right > window.innerWidth,

                overflow_y:
                    rect.bottom > window.innerHeight,

                scroll_width:
                    el.scrollWidth,

                scroll_height:
                    el.scrollHeight,

                client_width:
                    el.clientWidth,

                client_height:
                    el.clientHeight,

                // --------------------------------
                // Accessibility
                // --------------------------------

                role:
                    el.getAttribute("role") || "",

                aria_label:
                    el.getAttribute("aria-label") || "",

                // --------------------------------
                // Images
                // --------------------------------

                src:
                    el.src || "",

                srcset:
                    el.srcset || "",

                sizes:
                    el.sizes || "",

                loading:
                    el.loading || "",

                natural_width:
                    el.naturalWidth || 0,

                natural_height:
                    el.naturalHeight || 0,

                // --------------------------------
                // Links
                // --------------------------------

                href:
                    el.href || ""

            });

        });

        return elements;

    }
    """)

    return [
        ResponsiveElement(**item)
        for item in data
    ]