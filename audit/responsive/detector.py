from .models import ResponsiveResult


def detect(page, device_name):
    data = page.evaluate("""
    () => {

        const oversized = [];
        const fixed = [];

        document.querySelectorAll("*").forEach(el => {

            const rect = el.getBoundingClientRect();

            if(rect.width > window.innerWidth + 5){
                oversized.push({
                    tag: el.tagName,
                    width: rect.width
                });
            }

            const style = getComputedStyle(el);

            if(style.position === "fixed"){
                fixed.push(el.tagName);
            }

        });

        return {
            width: window.innerWidth,
            height: window.innerHeight,
            scrollWidth: document.documentElement.scrollWidth,
            clientWidth: document.documentElement.clientWidth,
            oversized,
            fixed
        };
    }
    """)

    return ResponsiveResult(
        device=device_name,
        width=data["width"],
        height=data["height"],
        scroll_width=data["scrollWidth"],
        client_width=data["clientWidth"],
        oversized=data["oversized"],
        fixed_elements=data["fixed"],
    )