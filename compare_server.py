from flask import Flask, request, jsonify
import cv2
import os

app = Flask(__name__)

@app.route('/compare', methods=['POST'])
def compare_images():
    img1_path = request.args.get("img1")
    img2_path = request.args.get("img2")

    if not img1_path or not img2_path:
        return jsonify({"error": "Missing image paths", "img1": img1_path, "img2": img2_path}), 400

    # Normalize file paths (especially important on Windows)
    img1_path = os.path.normpath(img1_path)
    img2_path = os.path.normpath(img2_path)

    if not os.path.exists(img1_path) or not os.path.exists(img2_path):
        return jsonify({
            "error": "One or both image paths do not exist",
            "img1": img1_path,
            "img2": img2_path
        }), 404

    # Load grayscale images
    img1 = cv2.imread(img1_path, 0)
    img2 = cv2.imread(img2_path, 0)

    if img1 is None or img2 is None:
        return jsonify({"error": "Failed to load image(s)"}), 400

    # Feature matching using ORB
    orb = cv2.ORB_create()
    kp1, des1 = orb.detectAndCompute(img1, None)
    kp2, des2 = orb.detectAndCompute(img2, None)

    if des1 is None or des2 is None:
        return jsonify({
            "similar": False,
            "reason": "Low number of detectable features"
        })

    bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
    matches = bf.match(des1, des2)

    similarity_score = len(matches)

    return jsonify({
        "similar": similarity_score > 30,
        "matches": similarity_score,
        "img1": os.path.basename(img1_path),
        "img2": os.path.basename(img2_path)
    })

if __name__ == '__main__':
    app.run(port=5001, debug=True)
 