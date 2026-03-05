# Resolve and validate the path (including symlinks) to prevent path traversal
    base_real = os.path.realpath(base_path)
    full_real = os.path.realpath(os.path.join(base_real, filename))
    if os.path.commonpath([base_real, full_real]) != base_real:
        # Reject paths that escape the intended base directory
        return "Invalid file path", 400
    with open(full_real) as f:
