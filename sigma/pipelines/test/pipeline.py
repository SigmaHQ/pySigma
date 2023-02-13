from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation


def dummy_test_pipeline():
    return ProcessingPipeline(
        name="Test pipeline",
        allowed_backends={"test"},
        items=[
        ProcessingItem(FieldMappingTransformation({
            "fieldA": "mappedA",
        }))
    ])

def another_test_pipeline():
    return ProcessingPipeline(
        name="Test pipeline",
        allowed_backends={"another"},
        items=[
            ProcessingItem(
                transformation=AddConditionTransformation(conditions={ "EventID": 1 }),
                rule_conditions=[ LogsourceCondition(category="process_creation", product="windows") ],
            ),
        ],
    )
