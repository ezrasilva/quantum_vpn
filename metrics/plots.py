import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Load the dataset
df = pd.read_csv('resultados_benchmark.csv')

# Group by Algorithm and calculate mean and std
grouped = df.groupby('Algoritmo').agg({
    'Tempo_PQC_KeyGen_ms': ['mean', 'std'],
    'Tempo_PQC_Encap_ms': ['mean', 'std'],
    'Tempo_PQC_Decap_ms': ['mean', 'std'],
    'Tempo_QKD_Alice_ms': ['mean', 'std'],
    'Tempo_Total_Hibrido_ms': ['mean', 'std'],
    'Tempo_IPsec_Rekey_ms': ['mean', 'std']
}).reset_index()

# Flatten columns
grouped.columns = ['Algoritmo', 
                   'KeyGen_mean', 'KeyGen_std',
                   'Encap_mean', 'Encap_std',
                   'Decap_mean', 'Decap_std',
                   'QKD_Alice_mean', 'QKD_Alice_std',
                   'Total_Hybrid_mean', 'Total_Hybrid_std',
                   'IPsec_Rekey_mean', 'IPsec_Rekey_std']

print("Summary Statistics (With Latency):")
print(grouped)

# --- Plot 1: Isolated PQC Operations (Figure A) ---
algorithms = grouped['Algoritmo']
x = np.arange(len(algorithms))
width = 0.25

fig1, ax1 = plt.subplots(figsize=(10, 6))
rects1 = ax1.bar(x - width, grouped['KeyGen_mean'], width, label='KeyGen', yerr=grouped['KeyGen_std'], capsize=4)
rects2 = ax1.bar(x, grouped['Encap_mean'], width, label='Encap', yerr=grouped['Encap_std'], capsize=4)
rects3 = ax1.bar(x + width, grouped['Decap_mean'], width, label='Decap', yerr=grouped['Decap_std'], capsize=4)

ax1.set_ylabel('Tempo (ms)')
ax1.set_title('Figura A: Desempenho Isolado PQC (Matemática Pura)')
ax1.set_xticks(x)
ax1.set_xticklabels(algorithms)
ax1.legend()
ax1.set_yscale('log') # Log scale helps visualize small PQC times
ax1.grid(True, which="both", ls="-", alpha=0.2)

# --- Plot 2: Hybrid Overhead (Figure B) ---
fig2, ax2 = plt.subplots(figsize=(10, 6))

pqc_total = grouped['KeyGen_mean'] + grouped['Encap_mean'] + grouped['Decap_mean']
qkd_latency = grouped['QKD_Alice_mean'] 

# Stacked bars
ax2.bar(algorithms, qkd_latency, label='Latência QKD (API/Rede)')
ax2.bar(algorithms, pqc_total, bottom=qkd_latency, label='Custo Computacional PQC')

ax2.set_ylabel('Tempo (ms)')
ax2.set_title('Figura B: Impacto da Integração Híbrida (QKD Dominante)')
ax2.legend()
ax2.grid(True, axis='y', alpha=0.5)

# --- Plot 3: IPsec Rekey with Simulated WAN Latency (Figure C) ---
fig3, ax3 = plt.subplots(figsize=(10, 6))
rects_rekey = ax3.bar(algorithms, grouped['IPsec_Rekey_mean'], yerr=grouped['IPsec_Rekey_std'], capsize=5, color='orange', alpha=0.7)

ax3.set_ylabel('Tempo de Rekey (ms)')
ax3.set_title('Figura C: Handshake IPsec em Cenário WAN (Simulado)')
ax3.grid(True, axis='y', alpha=0.5)
# Add a horizontal line representing the "ideal" LAN performance for comparison context if needed, but keeping it clean is better.

# Save plots
fig1.savefig('figura_a_pqc_isolado_latency.png')
fig2.savefig('figura_b_overhead_qkd_latency.png')
fig3.savefig('figura_c_ipsec_rekey_latency.png')

print("Plots generated with latency data.")