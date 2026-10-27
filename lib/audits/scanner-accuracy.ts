export interface ScannerBenchmarkCase {
  expectedDetected: boolean;
  observedDetected: boolean;
}

export function calculateScannerAccuracy(
  cases: ScannerBenchmarkCase[],
): {
  total: number;
  correct: number;
  incorrect: number;
  accuracyPercent: number | null;
} {
  const total = cases.length;
  const correct = cases.filter(
    (entry) => entry.expectedDetected === entry.observedDetected,
  ).length;
  const incorrect = total - correct;
  const accuracyPercent = total === 0
    ? null
    : Number(((correct / total) * 100).toFixed(1));

  return {
    total,
    correct,
    incorrect,
    accuracyPercent,
  };
}
