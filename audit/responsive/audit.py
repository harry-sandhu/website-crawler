from .detector import detect

from .rules import (
    run_overflow_audit,
    run_touch_target_audit,
    run_hidden_audit,
    run_clipping_audit,
    run_navigation_audit,
    run_sticky_audit,
    run_image_audit,
)


def run_responsive_audit(page, screenshot_manager):
    issues = []

    for device_name, device in screenshot_manager.DEVICES.items():

        page.set_viewport_size({
            "width": device["width"],
            "height": device["height"],
        })

        # Give responsive layouts time to update
        page.wait_for_timeout(300)

        result = detect(page, device_name)

        issues.extend(run_overflow_audit(result))
        issues.extend(run_touch_target_audit(result))
        issues.extend(run_hidden_audit(result))
        issues.extend(run_clipping_audit(result))
        issues.extend(run_navigation_audit(result))
        issues.extend(run_sticky_audit(result))
        issues.extend(run_image_audit(result))

    return issues