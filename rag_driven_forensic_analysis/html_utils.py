#!/usr/bin/env python3
# Program is developed on Ubuntu 22.04.2 and Python 3.10.
# Utility functions to generate HTML reports for forensic analysis.
# Version: 1.0

from PIL import Image
import base64
from io import BytesIO


images = {
    "Observation": "images/search.png",
    "Technical Details": "images/technical_details.png",
    "Matched RAG Indicators": "images/ioc.png",
    "Reasoning": "images/reasoning.png",
    "Classification": "images/default.png",
    "Security Recommendations": "images/security_recomdation.png"
}


def resize_image(image_path, max_width):
    with Image.open(image_path) as img:
        width, height = img.size
        ratio = height / width
        new_height = int(max_width * ratio)
        resized_img = img.resize((max_width, new_height))
        buffer = BytesIO()
        resized_img.save(buffer, format="JPEG")
        img_b64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
    return img_b64


def add_section(title, img_path, content_html, list_len=0):
    image_section = ""
    if img_path:
        img_b64 = resize_image(img_path, 150 + list_len*1)
        image_section = f"""
    <div style="text-align: center;">
            <img src="data:image/jpeg;base64,{img_b64}" alt="Classification & Confidence" style="display:block; margin:auto;">
        </div>
    """
    return f"""
        <h2><i class="fas fa-eye icon"></i> {title}</h2>
<div style="display: flex; align-items: center; gap: 40px;">
            {image_section}
            {content_html}
        </div>
    """

def generate_html_report_from_json(json_data, output_file_name):
    if json_data['classification'] == "Malicious":
        images["Classification"] = "images/malware.png"
    elif json_data['classification'] == "Suspicious":
        images["Classification"] = "images/suspicious.png"
    elif json_data['classification'] == "Benign":
        images["Classification"] = "images/clean.png"
    #observation_points = [sentence.strip() + "." for sentence in json_data["observation"].split('. ') if sentence.strip()]
    #technical_details_points = [sentence.strip() + "." for sentence in json_data["Technical Details"].split('. ') if sentence.strip()]

    html_content = """
    <!DOCTYPE html>
    <html lang='en'>
    <head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Incident Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f8f9fa; color: #333; }}
        h1, h2 {{ color: #2c3e50; }}
        .section {{ display: flex; align-items: flex-start; background: #fff; padding: 15px; margin-bottom: 15px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .section img {{ width: 100px; height: auto; margin-right: 15px; border-radius: 5px; object-fit: contain; }}
        ul {{ margin: 10px 0 10px 20px; }}
        .icon {{ margin-right: 8px; color: #007bff; }}
        .classification {{ font-weight: bold; color: #d9534f; }}
        .confidence {{ font-weight: bold; color: #5cb85c; }}
    </style>
    </head>
    <body>
    <h1><i class='fas fa-shield-alt icon'></i> Incident Analysis Report</h1>
    """

    classification_html = f"""
    <ul>
        <li>Classification: {json_data['classification']}</li>
        <li>Threat: {json_data.get('Threat', 'NA')}</li>
        <li>Confidence: {json_data['confidence']}</li>
    """
    classification_html += f"""
    <li>Mitre Tactics: </li>
        <ul>{''.join(f'<li>{t} : {r}</li>' for t, r in zip(json_data["Tactics"], json_data["Reason for Tactics"]))}</ul>
        <li>Mitre Techniques: </li>
        <ul>{''.join(f'<li>{t} : {r}</li>' for t, r in zip(json_data["Techniques"], json_data["Reason for Techniques"]))}</ul>
        </ul>
    """
    html_content += add_section("Classification", images["Classification"], classification_html, len(json_data['Techniques']) + len(json_data["Tactics"]))

    if "observation" in json_data:
        obs_html = f"<ul>{''.join([f'<li>{point}</li>' for point in json_data['observation']])}</ul>"
        html_content += add_section("Observation", images["Observation"], obs_html, len(json_data['observation']))

    if "Technical Details" in json_data:
        tech_html = f"<ul>{''.join([f'<li>{point}</li>' for point in json_data['Technical Details']])}</ul>"
        html_content += add_section("Technical Details", images["Technical Details"], tech_html, len(json_data["Technical Details"]))


    if "matched_rag_indicators" in json_data:
        ioc_html = f"<ul>{''.join([f'<li>{ioc}</li>' for ioc in json_data['matched_rag_indicators']])}</ul>"
        html_content += add_section("Matched RAG Indicators", images["Matched RAG Indicators"], ioc_html, len(json_data['matched_rag_indicators']))


    if "reasoning" in json_data:
        reasoning_html = f"<ul>{''.join([f'<li>{ioc}</li>' for ioc in json_data['reasoning']])}</ul>"
        
        html_content += add_section("Reasoning", images["Reasoning"], reasoning_html, 1)
    if "Security Recommendations" in json_data:
        ioc_html = f"<ul>{''.join([f'<li>{ioc}</li>' for ioc in json_data['Security Recommendations']])}</ul>"
        html_content += add_section("Security Recommendations", images["Security Recommendations"], ioc_html, len(json_data['Security Recommendations']))
    html_content += "</body></html>"

    with open(output_file_name, "w", encoding="utf-8") as f:
        f.write(html_content)

    print("HTML report generated successfully:", output_file_name)
    
# Example usage:
# generate_html_report_from_json(your_json_data, "report.html")