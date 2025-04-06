import socket
import concurrent.futures
import time
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog

class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Escáner de Puertos Ético")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # Variables de control
        self.scanning = False
        self.stop_scan = False
        
        # Crear interfaz
        self.create_widgets()
        
    def create_widgets(self):
        # Frame de configuración
        config_frame = ttk.LabelFrame(self.root, text="Configuración del Escaneo", padding=10)
        config_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Campo de dirección IP
        ttk.Label(config_frame, text="Dirección IP:").grid(row=0, column=0, sticky=tk.W)
        self.ip_entry = ttk.Entry(config_frame, width=20)
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        # Opciones de escaneo
        ttk.Label(config_frame, text="Tipo de escaneo:").grid(row=1, column=0, sticky=tk.W)
        self.scan_type = tk.StringVar(value="common")
        ttk.Radiobutton(config_frame, text="Puertos comunes", variable=self.scan_type, value="common").grid(row=1, column=1, sticky=tk.W)
        ttk.Radiobutton(config_frame, text="Rango personalizado", variable=self.scan_type, value="range").grid(row=1, column=2, sticky=tk.W)
        ttk.Radiobutton(config_frame, text="Todos los puertos (1-65535)", variable=self.scan_type, value="all").grid(row=1, column=3, sticky=tk.W)
        
        # Campos para rango personalizado
        self.range_frame = ttk.Frame(config_frame)
        ttk.Label(self.range_frame, text="Desde:").pack(side=tk.LEFT)
        self.start_port = ttk.Entry(self.range_frame, width=6)
        self.start_port.pack(side=tk.LEFT, padx=5)
        ttk.Label(self.range_frame, text="Hasta:").pack(side=tk.LEFT)
        self.end_port = ttk.Entry(self.range_frame, width=6)
        self.end_port.pack(side=tk.LEFT, padx=5)
        self.range_frame.grid(row=2, column=1, columnspan=3, sticky=tk.W, pady=5)
        self.toggle_range_fields()
        
        # Botones de control
        button_frame = ttk.Frame(self.root)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.scan_button = ttk.Button(button_frame, text="Iniciar Escaneo", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Detener Escaneo", command=self.stop_scanning, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.save_button = ttk.Button(button_frame, text="Guardar Resultados", command=self.save_results, state=tk.DISABLED)
        self.save_button.pack(side=tk.LEFT, padx=5)
        
        # Área de resultados
        results_frame = ttk.LabelFrame(self.root, text="Resultados", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        
        # Barra de progreso
        self.progress = ttk.Progressbar(self.root, orient=tk.HORIZONTAL, mode='determinate')
        self.progress.pack(fill=tk.X, padx=10, pady=5)
        
        # Configurar el cierre de la ventana
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Actualizar campos según tipo de escaneo
        self.scan_type.trace_add('write', lambda *args: self.toggle_range_fields())
    
    def toggle_range_fields(self):
        if self.scan_type.get() == "range":
            self.range_frame.grid()
        else:
            self.range_frame.grid_remove()
    
    def escanear_puerto(self, ip, puerto, timeout=1):
        """Intenta conectarse a un puerto específico."""
        if self.stop_scan:
            return None
            
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                resultado = s.connect_ex((ip, puerto))
                if resultado == 0:
                    return puerto
                return None
        except Exception:
            return None
    
    def obtener_servicio(self, puerto):
        """Obtiene el nombre del servicio asociado al puerto."""
        try:
            return socket.getservbyport(puerto)
        except:
            return "desconocido"
    
    def start_scan(self):
        """Inicia el escaneo de puertos."""
        # Validar entrada
        ip = self.ip_entry.get()
        if not ip:
            messagebox.showerror("Error", "Por favor ingrese una dirección IP")
            return
            
        # Configurar puertos a escanear
        scan_type = self.scan_type.get()
        
        if scan_type == "common":
            puertos = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 5900, 8080]
        elif scan_type == "range":
            try:
                inicio = int(self.start_port.get())
                fin = int(self.end_port.get())
                if inicio < 1 or fin > 65535 or inicio > fin:
                    raise ValueError
                puertos = range(inicio, fin + 1)
            except ValueError:
                messagebox.showerror("Error", "Por favor ingrese un rango válido de puertos (1-65535)")
                return
        else:  # all
            puertos = range(1, 65536)
        
        # Configurar interfaz para escaneo
        self.scanning = True
        self.stop_scan = False
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.DISABLED)
        self.results_text.delete(1.0, tk.END)
        
        # Configurar barra de progreso
        self.progress["maximum"] = len(puertos)
        self.progress["value"] = 0
        
        # Mostrar información inicial
        self.results_text.insert(tk.END, f"[*] Iniciando escaneo de puertos en {ip}\n")
        self.results_text.insert(tk.END, f"[*] Escaneando {len(puertos)} puertos...\n\n")
        self.results_text.see(tk.END)
        self.root.update()
        
        # Iniciar escaneo en un hilo separado para no bloquear la GUI
        self.thread = concurrent.futures.ThreadPoolExecutor(max_workers=100)
        self.scan_future = self.thread.submit(self.run_scan, ip, puertos)
    
    def run_scan(self, ip, puertos):
        """Ejecuta el escaneo real en un hilo separado."""
        puertos_abiertos = []
        inicio_tiempo = time.time()
        total_puertos = len(puertos)
        
        try:
            # Usamos ThreadPoolExecutor para escaneo concurrente
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                futures = {executor.submit(self.escanear_puerto, ip, puerto): puerto for puerto in puertos}
                
                for i, futuro in enumerate(concurrent.futures.as_completed(futures)):
                    if self.stop_scan:
                        break
                        
                    puerto = futures[futuro]
                    try:
                        resultado = futuro.result()
                        if resultado is not None:
                            servicio = self.obtener_servicio(resultado)
                            mensaje = f"[+] Puerto {resultado}/TCP abierto - Servicio: {servicio}\n"
                            self.results_text.insert(tk.END, mensaje)
                            self.results_text.see(tk.END)
                            puertos_abiertos.append(resultado)
                    except Exception as e:
                        self.results_text.insert(tk.END, f"[-] Error al escanear puerto {puerto}: {e}\n")
                        self.results_text.see(tk.END)
                    
                    # Actualizar progreso
                    self.progress["value"] = i + 1
                    self.root.update()
        
        finally:
            fin_tiempo = time.time()
            tiempo_transcurrido = fin_tiempo - inicio_tiempo
            
            # Mostrar resumen
            self.results_text.insert(tk.END, f"\n[*] Escaneo completado en {tiempo_transcurrido:.2f} segundos\n")
            self.results_text.insert(tk.END, f"[*] Puertos abiertos encontrados: {len(puertos_abiertos)}\n")
            self.results_text.see(tk.END)
            
            # Guardar resultados para posible exportación
            self.scan_results = {
                "ip": ip,
                "open_ports": puertos_abiertos,
                "scan_time": tiempo_transcurrido,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            # Restaurar interfaz
            self.scanning = False
            self.scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.save_button.config(state=tk.NORMAL)
            self.root.update()
    
    def stop_scanning(self):
        """Detiene el escaneo en curso."""
        self.stop_scan = True
        self.results_text.insert(tk.END, "\n[!] Escaneo detenido por el usuario\n")
        self.results_text.see(tk.END)
    
    def save_results(self):
        """Guarda los resultados en un archivo."""
        if not hasattr(self, 'scan_results') or not self.scan_results['open_ports']:
            messagebox.showwarning("Advertencia", "No hay resultados para guardar")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Archivos de texto", "*.txt"), ("Todos los archivos", "*.*")],
            initialfile=f"scan_results_{self.scan_results['ip']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        
        if not file_path:
            return
            
        try:
            with open(file_path, 'w') as f:
                f.write(f"Resultados del escaneo de puertos\n")
                f.write(f"Fecha: {self.scan_results['timestamp']}\n")
                f.write(f"IP objetivo: {self.scan_results['ip']}\n")
                f.write(f"Tiempo de escaneo: {self.scan_results['scan_time']:.2f} segundos\n\n")
                f.write("Puertos abiertos:\n")
                for puerto in self.scan_results['open_ports']:
                    servicio = self.obtener_servicio(puerto)
                    f.write(f"{puerto}/TCP - {servicio}\n")
            
            messagebox.showinfo("Éxito", f"Resultados guardados en:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo guardar el archivo:\n{e}")
    
    def on_close(self):
        """Maneja el cierre de la ventana."""
        if self.scanning:
            if messagebox.askokcancel("Salir", "El escaneo está en progreso. ¿Realmente desea salir?"):
                self.stop_scanning()
                self.root.destroy()
        else:
            self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()