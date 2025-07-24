from sigma.processing.conditions import LogsourceCondition
from sigma.pipelines.base import Pipeline
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    AddConditionTransformation,
    FieldMappingTransformation,
)


@Pipeline
def dummy_test_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Test pipeline",
        allowed_backends=frozenset({"text_query_test"}),
        items=[
            ProcessingItem(
                FieldMappingTransformation(
                    {
                        "fieldA": "mappedA",
                    }
                )
            )
        ],
    )


def another_test_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Test pipeline",
        allowed_backends=frozenset({"another"}),
        items=[
            ProcessingItem(
                transformation=AddConditionTransformation(conditions={"EventID": 1}),
                rule_conditions=[
                    LogsourceCondition(category="process_creation", product="windows")
                ],
            ),
        ],
    )


class YetAnotherTestPipeline(Pipeline):
    def apply(self) -> ProcessingPipeline:
        return ProcessingPipeline(
            name="Yet Another Test pipeline",
            allowed_backends=frozenset({"another"}),
            items=[
                ProcessingItem(
                    transformation=AddConditionTransformation(conditions={"EventID": 1}),
                    rule_conditions=[
                        LogsourceCondition(category="process_creation", product="windows")
                    ],
                ),
            ],
        )
