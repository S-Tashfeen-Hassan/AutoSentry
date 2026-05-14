from continual_detector import ContinualDetector

# Create the detector
detector = ContinualDetector(
    encoder_path="encoder_for_inference.pth",
    faiss_index_path="faiss_index.idx",
    thresholds_path="thresholds.joblib",
    memory_path="normal_memory.npy",
    embedding_dim=64,   # must match your encoder output
    input_dim=78        # must match your preprocessing feature count
)

# Example preprocessed log
test_log = [0.87948656, 1.3528618, -0.22360651, 3.572857, 3.7197673, 0.50586927, 11.469458, 1.2630873, 1.2843541, 179.0095, 3.4197965, 0.49042776, 5.7716136, 0.13124256, 0.1248575, 1.0, 1.0, 0.0, 0.0, 0.000385282, 0.0, 113.0, 0.0, 4.0, 7.0, 4.0, 1.0, 1.0, 70.0, 147.0, 173.0, 0.0, 0.0]
# Run detection
result = detector.process_single(test_log)

print(result)
