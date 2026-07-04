from .models import (
    AuditScore,
    CategoryScore,
)

from .weights import (
    MAX_SCORE,
    MIN_SCORE,
    SEVERITY_WEIGHTS,
    CATEGORY_MULTIPLIERS,
)


class ScoreEngine:

    def calculate(self, report):

        score = AuditScore()

        # ----------------------------------
        # Count Issues
        # ----------------------------------

        categories = {}

        for issue in report.issues:

            score.total_issues += 1

            severity = issue.severity

            if severity == "Critical":
                score.critical += 1

            elif severity == "High":
                score.high += 1

            elif severity == "Medium":
                score.medium += 1

            elif severity == "Low":
                score.low += 1

            category = issue.category

            if category not in categories:

                categories[category] = {

                    "score": MAX_SCORE,

                    "deductions": 0,

                }

            deduction = (

                SEVERITY_WEIGHTS.get(severity, 0)
                *
                CATEGORY_MULTIPLIERS.get(category, 1)

            )

            categories[category]["score"] -= deduction
            categories[category]["deductions"] += deduction

        # ----------------------------------
        # Category Scores
        # ----------------------------------

        for category, values in categories.items():

            category_score = max(

                MIN_SCORE,

                round(values["score"], 1),

            )

            score.categories.append(

                CategoryScore(

                    name=category,

                    score=category_score,

                    deductions=round(
                        values["deductions"],
                        1,
                    ),

                )

            )

        score.categories.sort(
            key=lambda c: c.name
        )

        # ----------------------------------
        # Overall Score
        # ----------------------------------

        if score.categories:

            score.overall = round(

                sum(
                    category.score
                    for category in score.categories
                )
                /
                len(score.categories),

                1,

            )

        else:

            score.overall = MAX_SCORE

        return score