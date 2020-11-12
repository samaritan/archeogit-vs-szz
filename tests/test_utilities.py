from archeogitvsszz.utilities import Calculation


def test_get_recall_and_precision():
    # Normal Calculation
    contributors = {'1', '2', '3'}
    ground_truth = {'1', '3', '4'}

    expected_recall_and_precision = [2/3, 2/3]
    actual_recall_and_precision = Calculation.get_recall_and_precision(contributors, ground_truth)
    assert actual_recall_and_precision == expected_recall_and_precision

    # Recall 100% Calculation
    contributors = {'1', '2', '3', '4'}
    ground_truth = {'1', '3'}

    expected_recall_and_precision = [1.0, 0.5]
    actual_recall_and_precision = Calculation.get_recall_and_precision(contributors, ground_truth)
    assert actual_recall_and_precision == expected_recall_and_precision

    # Precision 100% Calculation
    contributors = {'1', '3'}
    ground_truth = {'1', '3', '5', '4'}

    expected_recall_and_precision = [0.5, 1.0]
    actual_recall_and_precision = Calculation.get_recall_and_precision(contributors, ground_truth)
    assert actual_recall_and_precision == expected_recall_and_precision

    # Recall and Precision 100% Calculation
    contributors = {'1', '3'}
    ground_truth = {'1', '3'}

    expected_recall_and_precision = [1.0, 1.0]
    actual_recall_and_precision = Calculation.get_recall_and_precision(contributors, ground_truth)
    assert actual_recall_and_precision == expected_recall_and_precision

    # Empty Sets Calculation
    contributors = set()
    ground_truth = set()

    expected_recall_and_precision = [0.0, 0.0]
    actual_recall_and_precision = Calculation.get_recall_and_precision(contributors, ground_truth)

    assert actual_recall_and_precision == expected_recall_and_precision

