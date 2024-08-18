import os

import tkinter as tk

from tkinter.scrolledtext import ScrolledText

from tkinter import ttk, messagebox

from scapy.all import *

import threading

import time

import socket

from queue import Queue

from ipwhois import IPWhois

import requests

from reportlab.lib.pagesizes import letter

from reportlab.lib import colors

from reportlab.lib.styles import getSampleStyleSheet

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

from datetime import datetime



class PortScanner:

    def __init__(self):

        self.scanning = False

        self.open_ports = []

        self.start_time = None

        self.end_time = None

        self.total_ports = 0

        self.ports_scanned = 0

        self.ip_address = None

        self.report_folder = "reports"



        # Create the reports directory if it doesn't exist



        if not os.path.exists(self.report_folder):

            os.makedirs(self.report_folder)



    def resolve_host(self, host):

        try:

            return socket.gethostbyname(host)

        except socket.gaierror:

            messagebox.showerror("Error", "Invalid IP address or web address.")

            return None



    def reverse_dns(self, ip_address):

        try:

            return socket.gethostbyaddr(ip_address)[0]

        except socket.herror:

            return "No reverse DNS found"



    def geoip_lookup(self, ip_address):

        try:

            response = requests.get(f"http://ip-api.com/json/{ip_address}")

            data = response.json()

            if data["status"] == "success":

                return f"{data['country']}, {data['regionName']}, {data['city']}"

            else:

                return "GeoIP lookup failed"

        except Exception:

            return "GeoIP lookup failed"



    def whois_lookup(self, ip_address):

        try:

            obj = IPWhois(ip_address)

            results = obj.lookup_rdap()

            return results['asn_description']

        except Exception:

            return "WHOIS lookup failed"



    def ping_host(self, ip_address):

        response = sr1(IP(dst=ip_address) / ICMP(), timeout=2, verbose=False)

        return response is not None



    def detect_os(self, ip_address):

        response = sr1(IP(dst=ip_address) / ICMP(), timeout=1, verbose=False)

        if response:

            ttl = response.ttl

            if ttl <= 64:

                return "Linux/Unix"

            elif ttl <= 128:

                return "Windows"

        return "Unknown"



    def scan_port(self, ip_address, port, results, progress_bar):

        if not self.scanning:

            return

        syn_packet = IP(dst=ip_address) / TCP(sport=RandShort(), dport=port, flags="S")

        response = sr1(syn_packet, timeout=1, verbose=False)



        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:

            results.put(port)

            sr(IP(dst=ip_address) / TCP(sport=RandShort(), dport=port, flags="R"), timeout=1, verbose=False)

        self.ports_scanned += 1

        progress = (self.ports_scanned / self.total_ports) * 100

        progress_bar["value"] = progress







    def scan_ports(self, ip_address, start_port=1, end_port=1000, progress_bar=None):

        self.open_ports = []

        self.start_time = time.time()

        self.total_ports = end_port - start_port + 1

        self.ports_scanned = 0



        results = Queue()

        threads = []



        self.ip_address = ip_address

        for port in range(start_port, end_port + 1):

            if not self.scanning:

                break



            t = threading.Thread(target=self.scan_port, args=(ip_address, port, results, progress_bar))

            threads.append(t)

            t.start()



        for t in threads:

            t.join()



        while not results.empty():

            self.open_ports.append(results.get())



        self.end_time = time.time()

        self.display_results(ip_address)



    def stop_scan(self):

        self.scanning = False

        if self.ip_address:

            self.display_results(self.ip_address)



    def display_results(self, ip_address=None):

        progress_text.config(state=tk.NORMAL)

        progress_text.delete(1.0, tk.END)

        if ip_address:

            os_info = self.detect_os(ip_address)

            reverse_dns = self.reverse_dns(ip_address)

            geoip_info = self.geoip_lookup(ip_address)

            whois_info = self.whois_lookup(ip_address)

            

            progress_text.insert(tk.END, f"Host: {ip_address} (OS: {os_info})\n")

            progress_text.insert(tk.END, f"Reverse DNS: {reverse_dns}\n")

            progress_text.insert(tk.END, f"Location: {geoip_info}\n")

            progress_text.insert(tk.END, f"WHOIS: {whois_info}\n")



        if self.open_ports:

            progress_text.insert(tk.END, "Open ports and Services:\n")

            for port in self.open_ports:

                try:

                    service = socket.getservbyport(port, "tcp")

                except:

                    service = "Unknown"



                progress_text.insert(tk.END, f"Port {port}: {service}\n")



        else:

            progress_text.insert(tk.END, "No open ports found.\n")

        if self.start_time and self.end_time:

            progress_text.insert(tk.END, f"Scan completed in {self.end_time - self.start_time:.2f} seconds\n")

        progress_text.config(state=tk.DISABLED)

        self.generate_report(ip_address)



        # Add the pop-up message only if not stopping the scan

        if self.scanning:

            messagebox.showinfo("Scan Complete", "The scan has been completed successfully.")



       

        # Display message in the progress bar

        '''progress_bar["value"] = 100

        progress_text.config(state=tk.NORMAL)

        progress_text.insert(tk.END, "Scan has been completed.\n")

        progress_text.config(state=tk.DISABLED)'''



    def generate_report(self, ip_address):

        os_info = self.detect_os(ip_address)

        reverse_dns = self.reverse_dns(ip_address)

        geoip_info = self.geoip_lookup(ip_address)

        whois_info = self.whois_lookup(ip_address)

        self.save_report_as_pdf(ip_address, os_info, reverse_dns, geoip_info, whois_info)



    def save_report_as_pdf(self, ip_address, os_info, reverse_dns, geoip_info, whois_info):

        date_str = datetime.now().strftime("%Y%m%d")

        file_path = os.path.join(self.report_folder, f"Nscan_{ip_address}_{date_str}.pdf")

        doc = SimpleDocTemplate(file_path, pagesize=letter)

        styles = getSampleStyleSheet()

        elements = []



        elements.append(Paragraph("Network Scan Report", styles['Title']))

        elements.append(Spacer(1, 12))

        elements.append(Paragraph(f"Host: {ip_address}", styles['Normal']))

        elements.append(Paragraph(f"Operating System: {os_info}", styles['Normal']))

        elements.append(Paragraph(f"Reverse DNS: {reverse_dns}", styles['Normal']))

        elements.append(Paragraph(f"Location: {geoip_info}", styles['Normal']))

        elements.append(Paragraph(f"WHOIS Information: {whois_info}", styles['Normal']))

        elements.append(Spacer(1, 12))

        

        if self.open_ports:

            data = [["Port", "Service"]]

            for port in self.open_ports:

                try:

                    service = socket.getservbyport(port, "tcp")



                except:

                    service = "Unknown"



                data.append([str(port), service])



            table = Table(data)

            table.setStyle(TableStyle([

                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),

                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),

                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),

                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),

                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),

                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),

                ('GRID', (0, 0), (-1, -1), 1, colors.black),

            ]))



            elements.append(table)



        else:

            elements.append(Paragraph("No open ports found.", styles['Normal']))

        elements.append(Spacer(1, 12))

        



        # Check if start_time and end_time are set before calculating the scan duration

        if self.start_time and self.end_time:

            elements.append(Paragraph(f"Scan completed in {self.end_time - self.start_time:.2f} seconds", styles['Normal']))

		

        elements.append(Spacer(1, 12))

        

            # Adding Security Recommendations

        elements.append(Paragraph("Security Recommendations", styles['Heading2']))

        elements.append(Paragraph("1. Close unnecessary open ports to reduce attack surface.", styles['Normal']))

        elements.append(Paragraph("2. Use firewalls to block unauthorized access to open ports.", styles['Normal']))

        elements.append(Paragraph("3. Regularly update and patch systems to fix known vulnerabilities.", styles['Normal']))

        elements.append(Paragraph("4. Monitor network traffic for suspicious activities.", styles['Normal']))

        elements.append(Paragraph("5. Implement Intrusion Detection/Prevention Systems (IDS/IPS).", styles['Normal']))

        

        elements.append(Spacer(1, 12))



        elements.append(PageBreak())



        doc.build(elements, onFirstPage=self.add_page_border, onLaterPages=self.add_page_border)



    def add_page_border(self, canvas, doc):

        canvas.saveState()

        canvas.setStrokeColorRGB(0, 0, 0)

        canvas.setLineWidth(2)

        margin = 36  # 0.5 inch margin

        width, height = doc.pagesize

        canvas.rect(margin, margin, width - 2*margin, height - 2*margin)

        canvas.restoreState()



def scan_button_clicked():

    host = ip_entry.get().strip()

    ip_address = port_scanner.resolve_host(host)

    if ip_address:

        if port_scanner.ping_host(ip_address):

            progress_text.config(state=tk.NORMAL)

            progress_text.delete(1.0, tk.END)

            progress_bar["value"] = 0

            port_scanner.scanning = True

            threading.Thread(target=port_scanner.scan_ports, args=(ip_address, 1, 1000, progress_bar)).start()



        else:

            progress_text.config(state=tk.NORMAL)

            progress_text.delete(1.0, tk.END)

            progress_text.insert(tk.END, f"Host {host} is not reachable.\n")

            progress_text.config(state=tk.DISABLED)



def stop_button_clicked():

    port_scanner.stop_scan()



def reset_button_clicked():

    port_scanner.stop_scan()

    ip_entry.delete(0, tk.END)

    progress_text.config(state=tk.NORMAL)

    progress_text.delete(1.0, tk.END)

    progress_text.config(state=tk.DISABLED)

    progress_bar["value"] = 0  # Reset progress bar



root = tk.Tk()

root.title("Network Scanner (Nscan)")

root.geometry("700x600")

root.configure(bg="#2c3e50")  # Set background color



style = ttk.Style()

style.configure("TButton", font=("Arial", 12), padding=10)

style.configure("TLabel", font=("Arial", 12), background="#2c3e50", foreground="#ecf0f1")

style.configure("TProgressbar", thickness=20)



# GUI Layout



tk.Label(root, text="Enter IP address or web address:", font=("Arial", 16), bg="#2c3e50", fg="#ecf0f1").pack(pady=(20, 10))

ip_entry = tk.Entry(root, font=("Arial", 14), bg="#ffffff", fg="#000000", insertbackground="#000000", relief="flat", bd=5)

ip_entry.pack(pady=(0, 20), padx=20, ipadx=10, ipady=5)



button_frame = tk.Frame(root, bg="#2c3e50")

button_frame.pack(pady=(0, 20))



scan_button = ttk.Button(button_frame, text="Scan", command=scan_button_clicked)

scan_button.grid(row=0, column=0, padx=10)



stop_button = ttk.Button(button_frame, text="Stop", command=stop_button_clicked)

stop_button.grid(row=0, column=1, padx=10)



reset_button = ttk.Button(button_frame, text="Reset", command=reset_button_clicked)

reset_button.grid(row=0, column=2, padx=10)



tk.Label(root, text="Scanning Progress:", font=("Arial", 16), bg="#2c3e50", fg="#ecf0f1").pack(pady=(10, 10))

progress_bar = ttk.Progressbar(root, orient="horizontal", length=500, mode="determinate")

progress_bar.pack(pady=(0, 20))



progress_text = ScrolledText(root, height=15, width=80, font=("Arial", 12), bg="#ffffff", fg="#000000", insertbackground="#000000", relief="flat", bd=5, state=tk.DISABLED)

progress_text.pack(pady=(0, 20))



port_scanner = PortScanner()

root.mainloop()

