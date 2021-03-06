/* Process model C++ form file: manet_dispatcher_head.pr.cpp */
/* Portions of this file copyright 1986-2008 by OPNET Technologies, Inc. */



/* This variable carries the header into the object file */
const char manet_dispatcher_head_pr_cpp [] = "MIL_3_Tfile_Hdr_ 145A 30A modeler 7 5944D93F 5944D93F 1 hp-PC hp 0 0 none none 0 0 none 0 0 0 0 0 0 0 0 1e80 8                                                                                                                                                                                                                                                                                                                                                                                                                 ";
#include <string.h>



/* OPNET system definitions */
#include <opnet.h>



/* Header Block */

/** Include files.					**/
#include <ip_higher_layer_proto_reg_sup.h>
#include <ip_rte_v4.h>
#include <ip_rte_support.h>
#include <ip_addr_v4.h>
#include <manet.h>
#include <oms_dist_support.h>
#include <oms_pr.h>
#include <oms_tan.h>
#include <oms_log_support.h>
#include <oms_sim_attr_cache.h>
#include<math.h>
#include<iostream>
//new


using namespace std;


/* Transition Macros*/
#define		SELF_INTERRUPT 		(OPC_INTRPT_SELF == intrpt_type)
#define		STREAM_INTERRUPT 	(OPC_INTRPT_STRM == intrpt_type)

////////////////////////////////////////////////////////////////////////////////
//Done by me
//msg type
// msg sent from global node to head
#define    head    1 

// msg sent from head
#define     key     2     
Prg_List * global_list;
Prg_List * part_list;
int *x;
const double RadioRange=80.0;
bool done=false,done2=false;

static unsigned char initkey[16]={0xA,0xE,0x3,0x2,0x9,0x2,0x3,0x2,0xE,0xA,0x6,0xD,0x0,0xD,0x7,0x3};
// static Prg_List *  ckey;

static unsigned char  initkey2[16]={0xD,0xF,0x3,0x8,0x7,0x6,0x4,0x7,0xB,0x5,0x3,0xC,0x9,0xE,0xF,0x5};
// Prg_List* symkey;// to store key for head

///end of code

//**********************************************************************************
/* Structure to hold information about a flow	*/
typedef struct ManetT_Flow_Info
	{
	int					row_index;
	OmsT_Dist_Handle	pkt_interarrival_dist_ptr;
	OmsT_Dist_Handle	pkt_size_dist_ptr;
	InetT_Address*		dest_address_ptr;
	double				stop_time;
	} ManetT_Flow_Info;

//Done by me

// def for handling msgs
 struct msg_info
	{
	int type;
	unsigned char info[16];
	//Prg_List * info;
	
	};

 struct node_info
	{
	int node_id;
	bool accessed;
	double x;
	double  y;
	
	};
 //End of code

/** Function prototypes.			**/
static void				manet_rpg_sv_init (void);
static void				manet_rpg_register_self (void);
static void				manet_rpg_sent_stats_update (double pkt_size);
static void				manet_rpg_received_stats_update (double pkt_size);
static void				manet_rpg_packet_flow_info_read (void);
static void				manet_rpg_generate_packet (void);
static void				manet_rpg_packet_destroy (Packet*	pkptr);
//Done By me
// new
void             		create_key(unsigned char arr[], Prg_List * list_neigh);
void                    create_list();
void                    re_create_list();
Prg_List *              check_dist();
Prg_List *             	region_query(PrgT_List* list,node_info * store);
void 					store_key(unsigned char key_arr[]);
double 					eculid_dist(node_info * tmp,node_info * tmp1);
void                    create_list_send(unsigned char key_arr[]);
void                    recreate_list_send(unsigned char key_arr[]);

//End code



//*************************************************************************************

/* End of Header Block */

#if !defined (VOSD_NO_FIN)
#undef	BIN
#undef	BOUT
#define	BIN		FIN_LOCAL_FIELD(_op_last_line_passed) = __LINE__ - _op_block_origin;
#define	BOUT	BIN
#define	BINIT	FIN_LOCAL_FIELD(_op_last_line_passed) = 0; _op_block_origin = __LINE__;
#else
#define	BINIT
#endif /* #if !defined (VOSD_NO_FIN) */



/* State variable definitions */
class manet_dispatcher_head_state
	{
	private:
		/* Internal state tracking for FSM */
		FSM_SYS_STATE

	public:
		manet_dispatcher_head_state (void);

		/* Destructor contains Termination Block */
		~manet_dispatcher_head_state (void);

		/* State Variables */
		Objid	                  		my_objid                                        ;	/* Object identifier of the surrounding module. */
		Objid	                  		my_node_objid                                   ;	/* Object identifier of the surrounding node. */
		Objid	                  		my_subnet_objid                                 ;	/* Object identifier of the surrounding subnet. */
		Stathandle	             		local_packets_received_hndl                     ;	/* Statictic handle for local packet throughput. */
		Stathandle	             		local_bits_received_hndl                        ;	/* Statictic handle for local bit throughput. */
		Stathandle	             		local_delay_hndl                                ;	/* Statictic handle for local end-to-end delay. */
		Stathandle	             		global_packets_received_hndl                    ;	/* Statictic handle for global packet throughput. */
		Stathandle	             		global_bits_received_hndl                       ;	/* Statictic handle for global bit throughput. */
		int	                    		outstrm_to_ip_encap                             ;	/* Index of the stream to ip_encap */
		int	                    		instrm_from_ip_encap                            ;	/* Index of the stream from ip_encap */
		ManetT_Flow_Info*	      		manet_flow_info_array                           ;	/* Information of the different flows */
		int	                    		higher_layer_proto_id                           ;	/* Protocol ID assigned by IP */
		Ici*	                   		ip_encap_req_ici_ptr                            ;	/* ICI to be associated with packets being sent to ip_encap */
		Stathandle	             		local_packets_sent_hndl                         ;
		Stathandle	             		local_bits_sent_hndl                            ;
		Stathandle	             		global_packets_sent_hndl                        ;
		Stathandle	             		global_bits_sent_hndl                           ;
		Stathandle	             		global_delay_hndl                               ;
		IpT_Interface_Info*	    		iface_info_ptr                                  ;	/* IP interface information for this station node */
		double	                 		next_pkt_interarrival                           ;
		Prg_List *	             		cluster_key                                     ;
		Prg_List *	             		symmetric_key                                   ;

		/* FSM code */
		void manet_dispatcher_head (OP_SIM_CONTEXT_ARG_OPT);
		/* Diagnostic Block */
		void _op_manet_dispatcher_head_diag (OP_SIM_CONTEXT_ARG_OPT);

#if defined (VOSD_NEW_BAD_ALLOC)
		void * operator new (size_t) throw (VOSD_BAD_ALLOC);
#else
		void * operator new (size_t);
#endif
		void operator delete (void *);

		/* Memory management */
		static VosT_Obtype obtype;
	};

VosT_Obtype manet_dispatcher_head_state::obtype = (VosT_Obtype)OPC_NIL;

#define my_objid                		op_sv_ptr->my_objid
#define my_node_objid           		op_sv_ptr->my_node_objid
#define my_subnet_objid         		op_sv_ptr->my_subnet_objid
#define local_packets_received_hndl		op_sv_ptr->local_packets_received_hndl
#define local_bits_received_hndl		op_sv_ptr->local_bits_received_hndl
#define local_delay_hndl        		op_sv_ptr->local_delay_hndl
#define global_packets_received_hndl		op_sv_ptr->global_packets_received_hndl
#define global_bits_received_hndl		op_sv_ptr->global_bits_received_hndl
#define outstrm_to_ip_encap     		op_sv_ptr->outstrm_to_ip_encap
#define instrm_from_ip_encap    		op_sv_ptr->instrm_from_ip_encap
#define manet_flow_info_array   		op_sv_ptr->manet_flow_info_array
#define higher_layer_proto_id   		op_sv_ptr->higher_layer_proto_id
#define ip_encap_req_ici_ptr    		op_sv_ptr->ip_encap_req_ici_ptr
#define local_packets_sent_hndl 		op_sv_ptr->local_packets_sent_hndl
#define local_bits_sent_hndl    		op_sv_ptr->local_bits_sent_hndl
#define global_packets_sent_hndl		op_sv_ptr->global_packets_sent_hndl
#define global_bits_sent_hndl   		op_sv_ptr->global_bits_sent_hndl
#define global_delay_hndl       		op_sv_ptr->global_delay_hndl
#define iface_info_ptr          		op_sv_ptr->iface_info_ptr
#define next_pkt_interarrival   		op_sv_ptr->next_pkt_interarrival
#define cluster_key             		op_sv_ptr->cluster_key
#define symmetric_key           		op_sv_ptr->symmetric_key

/* These macro definitions will define a local variable called	*/
/* "op_sv_ptr" in each function containing a FIN statement.	*/
/* This variable points to the state variable data structure,	*/
/* and can be used from a C debugger to display their values.	*/
#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE
#define FIN_PREAMBLE_DEC	manet_dispatcher_head_state *op_sv_ptr;
#define FIN_PREAMBLE_CODE	\
		op_sv_ptr = ((manet_dispatcher_head_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr));


/* Function Block */

#if !defined (VOSD_NO_FIN)
enum { _op_block_origin = __LINE__ + 2};
#endif

static void
manet_rpg_sv_init (void)
	{
	/** initializes all state variables used in this process model.	**/
	FIN (manet_rpg_sv_init ());

	/* Obtain the object identifiers for the surrounding module,	*/
	/* node and subnet.												*/
	my_objid         = op_id_self ();
	my_node_objid    = op_topo_parent (my_objid);
	my_subnet_objid  = op_topo_parent (my_node_objid);

		
	/* Create the ici that will be associated with packets being 	*/
	/* sent to IP.													*/
	ip_encap_req_ici_ptr = op_ici_create ("inet_encap_req");
	
	
	/* Register the local and global statictics.					*/
	
	local_packets_sent_hndl  	 = op_stat_reg ("MANET.Traffic Sent (packets/sec)",		OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	local_bits_sent_hndl		 = op_stat_reg ("MANET.Traffic Sent (bits/sec)",		OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	local_packets_received_hndl  = op_stat_reg ("MANET.Traffic Received (packets/sec)",	OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	local_bits_received_hndl	 = op_stat_reg ("MANET.Traffic Received (bits/sec)",	OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	local_delay_hndl             = op_stat_reg ("MANET.Delay (secs)",					OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL); 
	global_delay_hndl            = op_stat_reg ("MANET.Delay (secs)",					OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL); 
	global_packets_sent_hndl 	 = op_stat_reg ("MANET.Traffic Sent (packets/sec)",		OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL); 
	global_bits_sent_hndl		 = op_stat_reg ("MANET.Traffic Sent (bits/sec)",		OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL);
	global_packets_received_hndl = op_stat_reg ("MANET.Traffic Received (packets/sec)",	OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL); 
	global_bits_received_hndl	 = op_stat_reg ("MANET.Traffic Received (bits/sec)",	OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL);
	
	FOUT;
	}


static void
manet_rpg_register_self (void)
	{
	char				proc_model_name [128];
	OmsT_Pr_Handle		own_process_record_handle;
	Prohandle			own_prohandle;

	/** Get a higher layer protocol ID from IP and register this 	**/
	/** process in the model-wide process registry to be discovered **/
	/** by the lower layer.											**/
	FIN (rpg_dispatcher_register_self ());

	/* Register RPG as a higher layer protocol over IP layer 		*/
	/* and retrieve an auto-assigned protocol id.					*/
   	higher_layer_proto_id = IpC_Protocol_Unspec;
	Ip_Higher_Layer_Protocol_Register ("rpg", &higher_layer_proto_id);
	
	/* Obtain the process model name and process handle.			*/
	op_ima_obj_attr_get (my_objid, "process model", proc_model_name);
	own_prohandle = op_pro_self ();

	/* Register this process in the model-wide process registry		*/
	own_process_record_handle = (OmsT_Pr_Handle) oms_pr_process_register 
		(my_node_objid, my_objid, own_prohandle, proc_model_name);

	/* Set the protocol attribute to the same string we used in	*/
	/* Ip_Higher_Layer_Protocol_Register. Necessary for ip_encap*/
	/* to discover this process. Set the module object id also.	*/
	oms_pr_attr_set (own_process_record_handle,
					 "protocol", 		OMSC_PR_STRING, "rpg",
					 "module objid",	OMSC_PR_OBJID,	my_objid,
			 		 OPC_NIL);
	FOUT;
	}


static void
manet_rpg_sent_stats_update (double size)
	{
	/** This function updates the local and global statictics		**/
	/** related with packet sending.								**/
	FIN (manet_rpg_sent_stats_update (<args>));

	/* Update the local and global sent statistics.					*/
	op_stat_write (local_bits_sent_hndl,     size);
	op_stat_write (local_bits_sent_hndl,     0.0);
	op_stat_write (local_packets_sent_hndl,  1.0);
	op_stat_write (local_packets_sent_hndl,  0.0);
	op_stat_write (global_bits_sent_hndl,    size);
	op_stat_write (global_bits_sent_hndl,    0.0);
	op_stat_write (global_packets_sent_hndl, 1.0);
	op_stat_write (global_packets_sent_hndl, 0.0);
	
	FOUT;
	}

static void
manet_rpg_received_stats_update (double size)
	{
	/** This function updates the local and global statictics		**/
	/** related with packet sending.								**/
	FIN (manet_rpg_received_stats_update (<args>));

	/* Update the local and global sent statistics.					*/
	op_stat_write (local_bits_received_hndl,     size);
	op_stat_write (local_bits_received_hndl,     0.0);
	op_stat_write (local_packets_received_hndl,  1.0);
	op_stat_write (local_packets_received_hndl,  0.0);
	op_stat_write (global_bits_received_hndl,    size);
	op_stat_write (global_bits_received_hndl,    0.0);
	op_stat_write (global_packets_received_hndl, 1.0);
	op_stat_write (global_packets_received_hndl, 0.0);
	
	FOUT;
	}


static void
manet_rpg_packet_flow_info_read (void)
	{
	int							i, row_count;
	char						temp_str [256];
	char						interarrival_str [256];
	char						pkt_size_str [256];
	char						log_message_str [256];
	Objid						trafgen_params_comp_objid;
	Objid						ith_flow_attr_objid;
	double						start_time;
	InetT_Address*				dest_address_ptr;
	InetT_Address				dest_address;
	static OmsT_Log_Handle		manet_traffic_generation_log_handle;
	static Boolean				manet_traffic_generation_log_handle_not_created = OPC_TRUE;

	/** Read in the attributes for each flow	**/
	FIN (manet_rpg_packet_flow_info_read (void));

	/* Get a handle to the Traffic Generation Parameters compound attribute.*/
	op_ima_obj_attr_get (my_objid, "Traffic Generation Parameters", &trafgen_params_comp_objid);

	/* Obtain the row count 												*/
	row_count = op_topo_child_count (trafgen_params_comp_objid, OPC_OBJTYPE_GENERIC);

	/* If there are no flows specified, exit from the function				*/
	if (row_count == 0)
		{
		FOUT;
		}

	/* Allocate enough memory to hold all the information.					*/
	manet_flow_info_array = (ManetT_Flow_Info*) op_prg_mem_alloc (sizeof (ManetT_Flow_Info) * row_count);

	/* Loop through each row and read in the information specified.			*/
	for (i = 0; i < row_count; i++)
		{
		/* Get the object ID of the associated row for the ith child.		*/
		ith_flow_attr_objid = op_topo_child (trafgen_params_comp_objid, OPC_OBJTYPE_GENERIC, i);

		/* Read in the start time and stop times */
		op_ima_obj_attr_get (ith_flow_attr_objid, "Start Time", &start_time);
		op_ima_obj_attr_get (ith_flow_attr_objid, "Stop Time", &manet_flow_info_array [i].stop_time);

		/* Read in the packet inter-arrival time and packet size 			*/
		op_ima_obj_attr_get (ith_flow_attr_objid, "Packet Inter-Arrival Time", interarrival_str);
		op_ima_obj_attr_get (ith_flow_attr_objid, "Packet Size", pkt_size_str);

		/* Set the distribution handles	*/
		manet_flow_info_array [i].pkt_interarrival_dist_ptr = oms_dist_load_from_string (interarrival_str);
		manet_flow_info_array [i].pkt_size_dist_ptr = oms_dist_load_from_string (pkt_size_str);
	
		/* Read in the destination IP address.								*/
		op_ima_obj_attr_get (ith_flow_attr_objid, "Destination IP Address", temp_str);
		
		if (strcmp (temp_str, "auto assigned"))
			{
			/* Explicit destination address has been assigned	*/
			dest_address = inet_address_create (temp_str, InetC_Addr_Family_Unknown);
			manet_flow_info_array [i].dest_address_ptr = inet_address_create_dynamic (dest_address);
			inet_address_destroy (dest_address);
			}
		else
			{
			/* The destination address is set to auto-assigned	*/
			/* Choose a random destination address				*/
			dest_address_ptr = manet_rte_dest_ip_address_obtain (iface_info_ptr);
			manet_flow_info_array [i].dest_address_ptr = dest_address_ptr;
			if (dest_address_ptr == OPC_NIL)
				{
				/* Write a simulation log		*/
				char					my_node_name [64];
				
				op_ima_obj_attr_get_str (my_node_objid, "name", 64, my_node_name);
				
				if (manet_traffic_generation_log_handle_not_created)
					{
					manet_traffic_generation_log_handle = oms_log_handle_create (OpC_Log_Category_Configuration, "MANET", "Traffic Setup", 32, 0,
						"WARNING:\n"
						"The following list of MANET traffic sources do not have valid destinations:\n\n"
						"Node name						Traffic row index\n"
						"-----------------				--------------------\n",
						"SUGGESTION(S):\n" 
						"Make sure that 1 or more prefixes are available for the MANET source to send its traffic to.\n\n"
						"RESULT(S):\n"
						"No Traffic will be generated at the MANET source.");
					
					manet_traffic_generation_log_handle_not_created = OPC_FALSE;
					}
				
				sprintf (log_message_str, "%s\t\t\t\t\t\t\t%d\n", my_node_name, i);
				oms_log_message_append (manet_traffic_generation_log_handle, log_message_str);
 				}
			}
		
		/* Schedule an interrupt for the start time of this flow.			*/
		/* Use the row index as the interrupt code, so that we can handle	*/
		/* the interrupt correctly.											*/
		op_intrpt_schedule_self (start_time, i);
		}

	FOUT;
	}
static void
manet_rpg_generate_packet (void)
	{
	int				row_num;
	double			schedule_time;
	double			pksize;
	Packet*			pkt_ptr;
	InetT_Address	src_address;
	InetT_Address*	src_addr_ptr;
	InetT_Address*	copy_address_ptr;
	double   tf_scaling_factor = 1;
	
	
	
	/** A packet needs to be generated for a particular flow	**/
	/** Generate the packet of an appropriate size and send it	**/
	/** to IP. Also schedule an event for the next packet		**/
	/** generation time for this flow.							**/
	FIN (manet_rpg_generate_packet (void));
	
	
	/* Identify the right packet flow using the interrupt code	*/
	row_num = op_intrpt_code ();
	
	/* If no destination was found, exit						*/
	if (manet_flow_info_array [row_num].dest_address_ptr == OPC_NIL)
		FOUT;
	
	/* Schedule a self interrupt for the next packet generation	*/
	/* time. The netx packet generation time will be the current*/
	/* time + the packet inter-arrival time. The interrupt code	*/
	/* will be the row number.									*/
	tf_scaling_factor = Oms_Sim_Attr_Traffic_Scaling_Get ();
	next_pkt_interarrival = (oms_dist_nonnegative_outcome (manet_flow_info_array [row_num].pkt_interarrival_dist_ptr)) / (tf_scaling_factor);
	schedule_time = op_sim_time () + next_pkt_interarrival;
	
	/* Schedule the next inter-arrival if it is less than the	*/
	/* stop time for the flow									*/
	if ((manet_flow_info_array [row_num].stop_time == -1.0) ||
		(schedule_time < manet_flow_info_array [row_num].stop_time))
		{
		op_intrpt_schedule_self (op_sim_time () + next_pkt_interarrival, row_num);
		}

	/* Create an unformatted packet	*/
	pksize = (double) ceil (oms_dist_outcome (manet_flow_info_array [row_num].pkt_size_dist_ptr));

	/* Size of the packet must be a multiple of 8. The extra bits will not be modeled		*/
	pksize = pksize - fmod (pksize, 8.0);
		
	pkt_ptr = op_pk_create (pksize);
	
	
	
	
	/* Update the packet sent statistics	*/
	manet_rpg_sent_stats_update (pksize);
	
	/* Make a copy of the destination address	*/
	/* and set it in the ICI for ip_encap		*/
	copy_address_ptr = manet_flow_info_array [row_num].dest_address_ptr;
	
	/* Set the destination address in the ICI */
	op_ici_attr_set (ip_encap_req_ici_ptr, "dest_addr", copy_address_ptr);
	
	/* Set the source address of this node based on the	*/
	/* IP address family of the destination				*/
	if (inet_address_family_get (copy_address_ptr) == InetC_Addr_Family_v6)
		{
		/* The destination is a IPv6 address	*/
		/* Set the IPv6 source address			*/
		src_address = inet_rte_intf_addr_get (iface_info_ptr, InetC_Addr_Family_v6);
		}
	else
		{
		/* The destination is a IPv4 address	*/
		/* Set the IPv4 source address			*/
		src_address = inet_rte_intf_addr_get (iface_info_ptr, InetC_Addr_Family_v4);
		}
	
	/* Create the source address	*/
	src_addr_ptr = inet_address_create_dynamic (src_address);
	
	/* Set the source address in the ICI	*/
	op_ici_attr_set (ip_encap_req_ici_ptr, "src_addr", src_addr_ptr);

	/* install the ICI */
	op_ici_install (ip_encap_req_ici_ptr);
	
	/* Send the packet to ip_encap	*/
	
	/* Since we are reusing the ici we should use				*/
	/* op_pk_send_forced. Otherwise if two flows generate a 	*/
	/* packet at the same time, the second packet genration will*/
	/* overwrite the ici before the first packet is processed by*/
	/* ip_encap.												*/
	op_pk_send_forced (pkt_ptr, outstrm_to_ip_encap);
	
	
	/* Destroy the temorpary source address	*/
	inet_address_destroy_dynamic (src_addr_ptr);
	
	/* Uninstall the ICI */
	op_ici_install (OPC_NIL);
	
	
	FOUT;
	}


static void
manet_rpg_packet_destroy (Packet*	pkptr)//new 
	{

	double			delay;
	double			pk_size;
	

	/** Get a packet from IP and destroy it. Destroy	**/
	/** the accompanying ici also.						**/
	FIN (manet_rpg_packet_destroy (Packet*	pkptr));
	
	
	/* Remove the packet from stream	*/
	//pkptr = op_pk_get (instrm_from_ip_encap);
	
	/* Update the "Traffic Received" statistics	*/
	pk_size = (double) op_pk_total_size_get (pkptr);
	
	/* Update the statistics for the packet received	*/
	manet_rpg_received_stats_update (pk_size);
	
	/* Compute the delay	*/
	delay = op_sim_time () - op_pk_creation_time_get (pkptr);
	
	/* Update the "Delay" statistic	*/
	op_stat_write (local_delay_hndl, delay);
	op_stat_write (global_delay_hndl, delay);

	op_ici_destroy (op_intrpt_ici ());
	op_pk_destroy (pkptr);
	
	FOUT;
	}
//Done by me
//3
void create_key(unsigned char arr_key[], Prg_List * list_neigh) 	// if node is head
{
	
	Objid procid;//,node_id;
	Packet * pktptr;
	node_info * tmp;
	msg_info *msg;
	int j;
	
	
	//cout<< prg_list_size(list_neigh)<<"\n";
	for (int i = 0; i< prg_list_size(list_neigh); i++)
		{
		
		 tmp=(node_info *)prg_list_access(list_neigh,i);// send members
	

		 msg=new msg_info();	
		 msg->type=key;
		
		for(j=0;j<16;j++)
		{
			msg->info[j]=arr_key[j];
		
		}
		
		
	/*for(int i=0;i<16;i++)
			{
			//unsigned char * ch1=( unsigned char *)prg_list_access(msg->info,i);
			printf("%x",msg->info[i]);
			//cout<<*ch;
			
			}
			cout<<"\n";*/
	
		pktptr=op_pk_create(0);
	
		op_pk_fd_set (pktptr, 0, OPC_FIELD_TYPE_STRUCT, msg, sizeof(msg_info)*8,op_prg_mem_copy_create,op_prg_mem_free,sizeof(msg_info));		
	
		procid = op_id_from_name(tmp->node_id,OPC_OBJTYPE_PROC,"traf_src");
		manet_rpg_sent_stats_update (32.0+(16.0*8.0));
		op_pk_deliver(pktptr,procid,0);
		}
	
	
}

Prg_List* region_query(PrgT_List* list,node_info*  store)
{
	Prg_List * region;
	node_info * s;

	int j=0;
	region=prg_list_create();
	prg_list_init (region);

	
	for(int i=0;i<prg_list_size(list);i++)
		{
			 s=(node_info *)prg_list_access(list,i);
			 
			 if(s->node_id==store->node_id)
				 continue;
			if(RadioRange>=eculid_dist(store,s)&&(!s->accessed))
				{
				//cout<<"inserted "<<"\n";
					prg_list_insert(region,s,j);
					j++;
				
				}
		
		}

		//<<"in query"<<prg_list_size(region)<<"\n";
	
	
	return region;

}
 
//1
void create_list()
	{
	
	node_info * tmp;
	global_list=prg_list_create();
	prg_list_init (global_list);
		
	
	
	for (int i = 0; i< op_topo_object_count(OPC_OBJTYPE_NODE_MOB); i++)
		{	
		tmp=new node_info();
		tmp->node_id = op_topo_object(OPC_OBJTYPE_NODE_MOB,i);
		op_ima_obj_attr_get_dbl(tmp->node_id, "x position",&tmp->x);	
		op_ima_obj_attr_get_dbl(tmp->node_id, "y position", &tmp->y);
		//cout<<tmp->node_id<<" "<<tmp->x<<" "<<tmp->y<<"\n";
		tmp->accessed=false;
		prg_list_insert (global_list,tmp,i);
		
			
		}
	}


//4
void re_create_list()
	
	{
	node_info * tmp;
	for (int i = 0; i< prg_list_size(global_list); i++)
		{	
		
		tmp =(node_info *)prg_list_access(global_list,i);
		op_ima_obj_attr_get_dbl(tmp->node_id, "x position",&tmp->x);	
		op_ima_obj_attr_get_dbl(tmp->node_id, "y position", &tmp->y);
		tmp->accessed=false;
		
		
			
		}
	
	
	}


//2
Prg_List * check_dist()
	{
	
	int i,j;
	//cout<<"in check "<<op_sim_time()<<"\n";
	node_info* tmp;
	Prg_List * neigh_list,*list;
	Objid my_procid         = op_id_self ();
	Objid my_node_id    = op_topo_parent (my_procid);
	for (j = 0; j<prg_list_size(global_list); j++)
		{	
		
		tmp=(node_info *)prg_list_access(global_list,j);
		if(tmp->node_id==my_node_id)
		{
		
		tmp->accessed=true;
		
		neigh_list=region_query(global_list,tmp);
		
		break;
		}
		}
	
			
	

		
		
	for (int i = 0; i<prg_list_size(neigh_list); i++)
	{
	tmp=(node_info *)prg_list_access(neigh_list,i);
	tmp->accessed=true;

	}
	j=0;
	
	while(j<prg_list_size(neigh_list))
		{
		tmp=(node_info *)prg_list_access(neigh_list,j);

		list=region_query(global_list,tmp);
		for (i= 0; i<prg_list_size(list); i++)
			{
			
			tmp=(node_info *)prg_list_access(list,i);
	
			prg_list_insert(neigh_list,tmp,PRGC_LISTPOS_TAIL);
			tmp->accessed=true;
			}
		j++;
		}
	
	return neigh_list;

	
	
	}

double eculid_dist(node_info * tmp, node_info * point)
		
{	double dist;
	 dist=sqrt(pow(tmp->x-point->x,2)+pow(tmp->y-point->y,2));
	
	
	
	return dist;
	
}

void store_key(unsigned char key_arr[])
	{
	
	unsigned char * ch;
	FIN(store_keys(<args>));

	//cout<<"store"<<"\n";
				for(int i=0;i<16;i++)
				{
				ch=&key_arr[i];// access symkey
				prg_list_insert(symmetric_key,ch,i);
				ch=(unsigned char *)prg_list_access(symmetric_key,i);
				//printf("%x",*ch);
				}
				//cout<<"\n";
				
				FOUT;
	}

void create_list_send(unsigned char arr_key[])
	{
	
	InetT_Address   dest_address;
	IpT_Interface_Info** my_dest_ip;
	InetT_Address	src_address;
	InetT_Address*	src_addr_ptr;
	InetT_Address*	copy_address_ptr;
	node_info * tmp;
	msg_info * msg;
	Objid procid;
	Packet* pktptr;
	int j;
	global_list=prg_list_create();
	prg_list_init (global_list);
		
	
	FIN(create_list_send(<args>));
	for (int i = 0; i< op_topo_object_count(OPC_OBJTYPE_NODE_MOB); i++)
		{	
		tmp=new node_info();
		tmp->node_id = op_topo_object(OPC_OBJTYPE_NODE_MOB,i);
		op_ima_obj_attr_get_dbl(tmp->node_id, "x position",&tmp->x);	
		op_ima_obj_attr_get_dbl(tmp->node_id, "y position", &tmp->y);

		prg_list_insert (global_list,tmp,i);	
			
		}
	
	
	for (int k = 0; k< prg_list_size(global_list); k++)
		{
		
		 tmp=(node_info *)prg_list_access(global_list,k);// send members
	

		 msg=new msg_info();	
		 msg->type=key;
		
		for(j=0;j<16;j++)
		{
			msg->info[j]=arr_key[j];
		
		}
		 
		 pktptr=op_pk_create(0);
		op_pk_fd_set (pktptr, 0, OPC_FIELD_TYPE_STRUCT, msg, sizeof(msg_info)*8,op_prg_mem_copy_create,op_prg_mem_free,sizeof(msg_info));		
	
		procid = op_id_from_name(tmp->node_id,OPC_OBJTYPE_PROC,"traf_src");
		my_dest_ip = (IpT_Interface_Info**) op_ima_obj_svar_get(procid , "iface_info_ptr");
		
		if (ip_rte_intf_ip_version_active (*my_dest_ip, InetC_Addr_Family_v6) == OPC_TRUE)  
		{
			
			dest_address = inet_rte_intf_addr_get (*my_dest_ip, InetC_Addr_Family_v6);
			
		}
	else
		{
			
			dest_address = inet_rte_intf_addr_get (*my_dest_ip, InetC_Addr_Family_v4);
			//cout<<dest_address.address.ipv4_addr<<"\n";
			}
	
		copy_address_ptr = &dest_address;
	

	op_ici_attr_set (ip_encap_req_ici_ptr, "dest_addr", copy_address_ptr);
	
	
	if (inet_address_family_get (copy_address_ptr) == InetC_Addr_Family_v6)
		{
		
		src_address = inet_rte_intf_addr_get (iface_info_ptr, InetC_Addr_Family_v6);
		}
	else

		{
		
		src_address = inet_rte_intf_addr_get (iface_info_ptr, InetC_Addr_Family_v4);
		}
	
	
		src_addr_ptr = inet_address_create_dynamic (src_address);
		op_ici_attr_set (ip_encap_req_ici_ptr, "src_addr", src_addr_ptr);
		op_ici_install (ip_encap_req_ici_ptr);
	
		op_pk_send_forced (pktptr,outstrm_to_ip_encap);
		
	manet_rpg_sent_stats_update (op_pk_total_size_get(pktptr));
		inet_address_destroy_dynamic (src_addr_ptr);
	
	
			op_ici_install (OPC_NIL);
	
		}
	FOUT;

	}



void recreate_list_send(unsigned char arr_key[])
	{
	
	InetT_Address   dest_address;
	IpT_Interface_Info** my_dest_ip;
	InetT_Address	src_address;
	InetT_Address*	src_addr_ptr;
	InetT_Address*	copy_address_ptr;
	node_info * tmp;
	msg_info * msg;
	Objid procid;
	Packet* pktptr;
	
	FIN(recreate_list_send(<args>));
	
		for (int i = 0; i< prg_list_size(global_list); i++)
		{	
		
		tmp =(node_info *)prg_list_access(global_list,i);
		op_ima_obj_attr_get_dbl(tmp->node_id, "x position",&tmp->x);	
		op_ima_obj_attr_get_dbl(tmp->node_id, "y position", &tmp->y);
		}
	
	for (int k = 0; k< prg_list_size(global_list); k++)
		{
		
		 tmp=(node_info *)prg_list_access(global_list,k);// send members
	

		 msg=new msg_info();	
		 msg->type=key;
		
		for(int j=0;j<16;j++)
		{
			msg->info[j]=arr_key[j];
		
		}
		 
		 pktptr=op_pk_create(0);
		op_pk_fd_set (pktptr, 0, OPC_FIELD_TYPE_STRUCT, msg, sizeof(msg_info)*8,op_prg_mem_copy_create,op_prg_mem_free,sizeof(msg_info));		
	
		procid = op_id_from_name(tmp->node_id,OPC_OBJTYPE_PROC,"traf_src");
				my_dest_ip = (IpT_Interface_Info**) op_ima_obj_svar_get(procid , "iface_info_ptr");
		
		if (ip_rte_intf_ip_version_active (*my_dest_ip, InetC_Addr_Family_v6) == OPC_TRUE)  
		{
			
			dest_address = inet_rte_intf_addr_get (*my_dest_ip, InetC_Addr_Family_v6);
			
		}
	else
		{
			
			dest_address = inet_rte_intf_addr_get (*my_dest_ip, InetC_Addr_Family_v4);
			//cout<<dest_address.address.ipv4_addr<<"\n";
			}
	
		copy_address_ptr = &dest_address;
	

	op_ici_attr_set (ip_encap_req_ici_ptr, "dest_addr", copy_address_ptr);
	
	
	if (inet_address_family_get (copy_address_ptr) == InetC_Addr_Family_v6)
		{
		
		src_address = inet_rte_intf_addr_get (iface_info_ptr, InetC_Addr_Family_v6);
		}
	else

		{
		
		src_address = inet_rte_intf_addr_get (iface_info_ptr, InetC_Addr_Family_v4);
		}
	
	
		src_addr_ptr = inet_address_create_dynamic (src_address);
		op_ici_attr_set (ip_encap_req_ici_ptr, "src_addr", src_addr_ptr);
		op_ici_install (ip_encap_req_ici_ptr);
	
		op_pk_send_forced (pktptr,outstrm_to_ip_encap);
			//op_pk_deliver(pktptr,procid,0);
			manet_rpg_sent_stats_update (op_pk_total_size_get(pktptr));

		inet_address_destroy_dynamic (src_addr_ptr);
	
	
			op_ici_install (OPC_NIL);
	
		}
	FOUT;

	}
//End of code
/* End of Function Block */

/* Undefine optional tracing in FIN/FOUT/FRET */
/* The FSM has its own tracing code and the other */
/* functions should not have any tracing.		  */
#undef FIN_TRACING
#define FIN_TRACING

#undef FOUTRET_TRACING
#define FOUTRET_TRACING

/* Undefine shortcuts to state variables because the */
/* following functions are part of the state class */
#undef my_objid
#undef my_node_objid
#undef my_subnet_objid
#undef local_packets_received_hndl
#undef local_bits_received_hndl
#undef local_delay_hndl
#undef global_packets_received_hndl
#undef global_bits_received_hndl
#undef outstrm_to_ip_encap
#undef instrm_from_ip_encap
#undef manet_flow_info_array
#undef higher_layer_proto_id
#undef ip_encap_req_ici_ptr
#undef local_packets_sent_hndl
#undef local_bits_sent_hndl
#undef global_packets_sent_hndl
#undef global_bits_sent_hndl
#undef global_delay_hndl
#undef iface_info_ptr
#undef next_pkt_interarrival
#undef cluster_key
#undef symmetric_key

/* Access from C kernel using C linkage */
extern "C"
{
	VosT_Obtype _op_manet_dispatcher_head_init (int * init_block_ptr);
	VosT_Address _op_manet_dispatcher_head_alloc (VosT_Obtype, int);
	void manet_dispatcher_head (OP_SIM_CONTEXT_ARG_OPT)
		{
		((manet_dispatcher_head_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr))->manet_dispatcher_head (OP_SIM_CONTEXT_PTR_OPT);
		}

	void _op_manet_dispatcher_head_svar (void *, const char *, void **);

	void _op_manet_dispatcher_head_diag (OP_SIM_CONTEXT_ARG_OPT)
		{
		((manet_dispatcher_head_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr))->_op_manet_dispatcher_head_diag (OP_SIM_CONTEXT_PTR_OPT);
		}

	void _op_manet_dispatcher_head_terminate (OP_SIM_CONTEXT_ARG_OPT)
		{
		/* The destructor is the Termination Block */
		delete (manet_dispatcher_head_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr);
		}


} /* end of 'extern "C"' */




/* Process model interrupt handling procedure */


void
manet_dispatcher_head_state::manet_dispatcher_head (OP_SIM_CONTEXT_ARG_OPT)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	FIN_MT (manet_dispatcher_head_state::manet_dispatcher_head ());
	try
		{
		/* Temporary Variables */
		List*					proc_record_handle_lptr;
		int						proc_record_handle_list_size;
		OmsT_Pr_Handle  		process_record_handle;
		Objid					low_module_objid;
		IpT_Rte_Module_Data*	ip_module_data_ptr;
		int						intrpt_type;
		int                     intrpt_code=0;
		
		
		/* End of Temporary Variables */


		FSM_ENTER ("manet_dispatcher_head")

		FSM_BLOCK_SWITCH
			{
			/*---------------------------------------------------------*/
			/** state (init) enter executives **/
			FSM_STATE_ENTER_UNFORCED_NOLABEL (0, "init", "manet_dispatcher_head [init enter execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_head [init enter execs]", state0_enter_exec)
				{
				/* Initialize the state variables used by this model.					*/
				manet_rpg_sv_init ();
				
				
				/* Register this process in the network wide process registery so that	*/
				/* lower layer can detect our existence.								*/
				manet_rpg_register_self ();
				
				/* Schedule a self interrupt to wait for lower layer process to			*/
				/* initialize and register itself in the model-wide process registry.	*/
				/* This is necessary since global RPG start time may have been set as	*/
				/* low as zero seconds, which is acceptable when operating over MAC		*/
				/* layer.																*/
				
				op_intrpt_schedule_self (op_sim_time (), 0);
				
				cluster_key=prg_list_create();
					prg_list_init(cluster_key);
					symmetric_key=prg_list_create();
				
				prg_list_init(symmetric_key);
				
				
				
							
				
				  
				
				}
				FSM_PROFILE_SECTION_OUT (state0_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (1,"manet_dispatcher_head")


			/** state (init) exit executives **/
			FSM_STATE_EXIT_UNFORCED (0, "init", "manet_dispatcher_head [init exit execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_head [init exit execs]", state0_exit_exec)
				{
				
				}
				FSM_PROFILE_SECTION_OUT (state0_exit_exec)


			/** state (init) transition processing **/
			FSM_TRANSIT_FORCE (2, state2_enter_exec, ;, "default", "", "init", "wait", "tr_31", "manet_dispatcher_head [init -> wait : default / ]")
				/*---------------------------------------------------------*/



			/** state (discover) enter executives **/
			FSM_STATE_ENTER_UNFORCED (1, "discover", state1_enter_exec, "manet_dispatcher_head [discover enter execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_head [discover enter execs]", state1_enter_exec)
				{
				/* Schedule a self interrupt, that will indicate the completion of		*/
				/* lower layer initializations. We will perform the discovery process	*/
				/* following the delivery of this interrupt, i.e. in the exit execs of	*/
				/* this state.															*/
				op_intrpt_schedule_self (op_sim_time (), 0);
				}
				FSM_PROFILE_SECTION_OUT (state1_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (3,"manet_dispatcher_head")


			/** state (discover) exit executives **/
			FSM_STATE_EXIT_UNFORCED (1, "discover", "manet_dispatcher_head [discover exit execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_head [discover exit execs]", state1_exit_exec)
				{
				/** In this state we try to discover the IP module	**/
				
				/* First check whether we have an IP module in the same node.			*/
				proc_record_handle_lptr = op_prg_list_create ();
				oms_pr_process_discover (my_objid, proc_record_handle_lptr,
										 "node objid",	OMSC_PR_OBJID,		my_node_objid,
										 "protocol", 	OMSC_PR_STRING,		"ip_encap",
										 OPC_NIL);
				
				/* Check the number of modules matching to the given discovery query.	*/
				proc_record_handle_list_size = op_prg_list_size (proc_record_handle_lptr);
				if (proc_record_handle_list_size != 1)
					{
					/* A node with multiple IP modules is not an acceptable				*/
					/* configuration. Terminate the simulation.							*/
					op_sim_end ("Error: Zero or Multiple IP modules are found in the surrounding node.", "", "", "");
					}
				else
					{
					/* We have exactly one ip_encap module in the surrounding node and	*/
					/* we should be running over this module. Get a handle to its		*/
					/* process record.													*/
					process_record_handle = (OmsT_Pr_Handle) op_prg_list_access (proc_record_handle_lptr, OPC_LISTPOS_HEAD);
				
					/* Obtain the module objid of the IP-ENCAP module and using that	*/
					/* determine our stream numbers with the lower layer.				*/
					oms_pr_attr_get (process_record_handle, "module objid", OMSC_PR_OBJID, &low_module_objid);
					oms_tan_neighbor_streams_find (my_objid, low_module_objid, &instrm_from_ip_encap, &outstrm_to_ip_encap);
					}
				
				/* 	Deallocate no longer needed process registry 		*/
				/*	information. 										*/
				while (op_prg_list_size (proc_record_handle_lptr))
					op_prg_list_remove (proc_record_handle_lptr, OPC_LISTPOS_HEAD);
				op_prg_mem_free (proc_record_handle_lptr);
				
				
				/* 	Obtain the IP interface information for the local 	*/
				/*	ip process from the model-wide registry. 			*/
				proc_record_handle_lptr = op_prg_list_create ();
				oms_pr_process_discover (OPC_OBJID_INVALID, proc_record_handle_lptr, 
					"node objid",	OMSC_PR_OBJID,		my_node_objid,
					"protocol", 	OMSC_PR_STRING,		"ip", 
					OPC_NIL);
				
				proc_record_handle_list_size = op_prg_list_size (proc_record_handle_lptr);
				if (proc_record_handle_list_size != 1)
					{
					/* 	An error should be created if there are more 	*/
					/*	than one ip process in the local node, or		*/
					/*	if no match is found. 							*/
					op_sim_end ("Error: either zero or several ip processes found in the local node", "", "", "");
					}
				else
					{
					/*	Obtain a handle on the process record.			*/
					process_record_handle = (OmsT_Pr_Handle) op_prg_list_access (proc_record_handle_lptr, OPC_LISTPOS_HEAD);
				
					/* Obtain a pointer to the ip module data	. 		*/
					oms_pr_attr_get (process_record_handle,	"module data", OMSC_PR_POINTER, &ip_module_data_ptr);	
					}
				
				/* 	Deallocate no longer needed process registry 		*/
				/*	information. 										*/
				while (op_prg_list_size (proc_record_handle_lptr))
					op_prg_list_remove (proc_record_handle_lptr, OPC_LISTPOS_HEAD);
				op_prg_mem_free (proc_record_handle_lptr);
				
				/* Get the IP address of this station node	*/
				/* Since this node can have only one		*/
				/* interface, access index 0				*/
				iface_info_ptr = inet_rte_intf_tbl_access (ip_module_data_ptr,0);
				
				/* Register this node's IP address in the global	*/
				/* list of IP address for auto assignment of a		*/
				/* destination address								*/
				manet_rte_ip_address_register (iface_info_ptr);
				}
				FSM_PROFILE_SECTION_OUT (state1_exit_exec)


			/** state (discover) transition processing **/
			FSM_TRANSIT_FORCE (3, state3_enter_exec, ;, "default", "", "discover", "wait_2", "tr_40", "manet_dispatcher_head [discover -> wait_2 : default / ]")
				/*---------------------------------------------------------*/



			/** state (wait) enter executives **/
			FSM_STATE_ENTER_UNFORCED (2, "wait", state2_enter_exec, "manet_dispatcher_head [wait enter execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_head [wait enter execs]", state2_enter_exec)
				{
				/* Wait for one more wave of interrupts to gurantee that lower layers	*/
				/* will have finalized their address resolution when we query for the	*/
				/* address (and other) information in the exit execs of discover state.	*/
				
				op_intrpt_schedule_self (op_sim_time (), 0);
				
				}
				FSM_PROFILE_SECTION_OUT (state2_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (5,"manet_dispatcher_head")


			/** state (wait) exit executives **/
			FSM_STATE_EXIT_UNFORCED (2, "wait", "manet_dispatcher_head [wait exit execs]")


			/** state (wait) transition processing **/
			FSM_TRANSIT_FORCE (4, state4_enter_exec, ;, "default", "", "wait", "wait_0", "tr_37", "manet_dispatcher_head [wait -> wait_0 : default / ]")
				/*---------------------------------------------------------*/



			/** state (wait_2) enter executives **/
			FSM_STATE_ENTER_UNFORCED (3, "wait_2", state3_enter_exec, "manet_dispatcher_head [wait_2 enter execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_head [wait_2 enter execs]", state3_enter_exec)
				{
				/** Wait so that all nodes can register their		**/
				/** own addresses in the global list of possible	**/
				/** IP destinations.								**/
				op_intrpt_schedule_self (op_sim_time (), 0);
				
					
					
				
				
				
				
							
				
				}
				FSM_PROFILE_SECTION_OUT (state3_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (7,"manet_dispatcher_head")


			/** state (wait_2) exit executives **/
			FSM_STATE_EXIT_UNFORCED (3, "wait_2", "manet_dispatcher_head [wait_2 exit execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_head [wait_2 exit execs]", state3_exit_exec)
				{
				/* Read in the traffic flow information	*/
				manet_rpg_packet_flow_info_read ();
				
				//cout<<op_sim_time()<<"\n";
				}
				FSM_PROFILE_SECTION_OUT (state3_exit_exec)


			/** state (wait_2) transition processing **/
			FSM_TRANSIT_FORCE (6, state6_enter_exec, ;, "default", "", "wait_2", "dispatch", "tr_48", "manet_dispatcher_head [wait_2 -> dispatch : default / ]")
				/*---------------------------------------------------------*/



			/** state (wait_0) enter executives **/
			FSM_STATE_ENTER_UNFORCED (4, "wait_0", state4_enter_exec, "manet_dispatcher_head [wait_0 enter execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_head [wait_0 enter execs]", state4_enter_exec)
				{
				/** Wait so that all nodes can register their		**/
				/** own addresses in the global list of possible	**/
				/** IP destinations.								**/
				op_intrpt_schedule_self (op_sim_time (), 0);
				}
				FSM_PROFILE_SECTION_OUT (state4_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (9,"manet_dispatcher_head")


			/** state (wait_0) exit executives **/
			FSM_STATE_EXIT_UNFORCED (4, "wait_0", "manet_dispatcher_head [wait_0 exit execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_head [wait_0 exit execs]", state4_exit_exec)
				{
				
				}
				FSM_PROFILE_SECTION_OUT (state4_exit_exec)


			/** state (wait_0) transition processing **/
			FSM_TRANSIT_FORCE (5, state5_enter_exec, ;, "default", "", "wait_0", "wait_1", "tr_39", "manet_dispatcher_head [wait_0 -> wait_1 : default / ]")
				/*---------------------------------------------------------*/



			/** state (wait_1) enter executives **/
			FSM_STATE_ENTER_UNFORCED (5, "wait_1", state5_enter_exec, "manet_dispatcher_head [wait_1 enter execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_head [wait_1 enter execs]", state5_enter_exec)
				{
				/** Wait so that all nodes can register their		**/
				/** own addresses in the global list of possible	**/
				/** IP destinations.								**/
				op_intrpt_schedule_self (op_sim_time (), 0);
				}
				FSM_PROFILE_SECTION_OUT (state5_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (11,"manet_dispatcher_head")


			/** state (wait_1) exit executives **/
			FSM_STATE_EXIT_UNFORCED (5, "wait_1", "manet_dispatcher_head [wait_1 exit execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_head [wait_1 exit execs]", state5_exit_exec)
				{
				
				}
				FSM_PROFILE_SECTION_OUT (state5_exit_exec)


			/** state (wait_1) transition processing **/
			FSM_TRANSIT_FORCE (1, state1_enter_exec, ;, "default", "", "wait_1", "discover", "tr_32", "manet_dispatcher_head [wait_1 -> discover : default / ]")
				/*---------------------------------------------------------*/



			/** state (dispatch) enter executives **/
			FSM_STATE_ENTER_UNFORCED (6, "dispatch", state6_enter_exec, "manet_dispatcher_head [dispatch enter execs]")

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (13,"manet_dispatcher_head")


			/** state (dispatch) exit executives **/
			FSM_STATE_EXIT_UNFORCED (6, "dispatch", "manet_dispatcher_head [dispatch exit execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_head [dispatch exit execs]", state6_exit_exec)
				{
				/* Get the interrupt type. This will be used to determine	*/
				/* whether this is a self interrupt to generate a packet or	*/
				/* a stream interrupt from ip_encap.						*/
				
				int  x;
				
				Packet * rcvd_pkt=OPC_NIL;
				
				
				//cout<<op_sim_time()<<"\n";
				
					//if(op_sim_time()>1)
					//{
						
					if(!done)	
					{
					//create_list_send(initkey);
					create_list();
					part_list=check_dist();
					create_key(initkey,part_list);	
					store_key(initkey);
					done=true;
					
					}
					
					//}
				
				
				
				
				if(op_sim_time()>90)
					{
					//cout<<op_sim_time()<<"\n";
					if(!done2)	
					{
					done2=true;
					//recreate_list_send(initkey2);
					
					re_create_list();
					part_list=check_dist();
					create_key(initkey2,part_list);
					store_key(initkey2);
					
					}
					
					}
				
				//msg_info * msg=new msg_info();
				
				intrpt_type = op_intrpt_type ();
				
				if (intrpt_type==OPC_INTRPT_STRM)
					{
				rcvd_pkt=op_pk_get (op_intrpt_strm ());
				
						x=op_pk_fd_max_index(rcvd_pkt);
					
						if(x<0)
						{	
						//cout<<x<<"\n";	
						manet_rpg_packet_destroy(rcvd_pkt);
						}
					}
				}
				FSM_PROFILE_SECTION_OUT (state6_exit_exec)


			/** state (dispatch) transition processing **/
			FSM_PROFILE_SECTION_IN ("manet_dispatcher_head [dispatch trans conditions]", state6_trans_conds)
			FSM_INIT_COND (SELF_INTERRUPT)
			FSM_DFLT_COND
			FSM_TEST_LOGIC ("dispatch")
			FSM_PROFILE_SECTION_OUT (state6_trans_conds)

			FSM_TRANSIT_SWITCH
				{
				FSM_CASE_TRANSIT (0, 6, state6_enter_exec, manet_rpg_generate_packet ();, "SELF_INTERRUPT", "manet_rpg_generate_packet ()", "dispatch", "dispatch", "tr_36", "manet_dispatcher_head [dispatch -> dispatch : SELF_INTERRUPT / manet_rpg_generate_packet ()]")
				FSM_CASE_TRANSIT (1, 6, state6_enter_exec, ;, "default", "", "dispatch", "dispatch", "tr_47", "manet_dispatcher_head [dispatch -> dispatch : default / ]")
				}
				/*---------------------------------------------------------*/



			}


		FSM_EXIT (0,"manet_dispatcher_head")
		}
	catch (...)
		{
		Vos_Error_Print (VOSC_ERROR_ABORT,
			(const char *)VOSC_NIL,
			"Unhandled C++ exception in process model (manet_dispatcher_head)",
			(const char *)VOSC_NIL, (const char *)VOSC_NIL);
		}
	}




void
manet_dispatcher_head_state::_op_manet_dispatcher_head_diag (OP_SIM_CONTEXT_ARG_OPT)
	{
	/* No Diagnostic Block */
	}

void
manet_dispatcher_head_state::operator delete (void* ptr)
	{
	FIN (manet_dispatcher_head_state::operator delete (ptr));
	Vos_Poolmem_Dealloc (ptr);
	FOUT
	}

manet_dispatcher_head_state::~manet_dispatcher_head_state (void)
	{

	FIN (manet_dispatcher_head_state::~manet_dispatcher_head_state ())


	/* No Termination Block */


	FOUT
	}


#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE

#define FIN_PREAMBLE_DEC
#define FIN_PREAMBLE_CODE

void *
manet_dispatcher_head_state::operator new (size_t)
#if defined (VOSD_NEW_BAD_ALLOC)
		throw (VOSD_BAD_ALLOC)
#endif
	{
	void * new_ptr;

	FIN_MT (manet_dispatcher_head_state::operator new ());

	new_ptr = Vos_Alloc_Object (manet_dispatcher_head_state::obtype);
#if defined (VOSD_NEW_BAD_ALLOC)
	if (new_ptr == VOSC_NIL) throw VOSD_BAD_ALLOC();
#endif
	FRET (new_ptr)
	}

/* State constructor initializes FSM handling */
/* by setting the initial state to the first */
/* block of code to enter. */

manet_dispatcher_head_state::manet_dispatcher_head_state (void) :
		_op_current_block (0)
	{
#if defined (OPD_ALLOW_ODB)
		_op_current_state = "manet_dispatcher_head [init enter execs]";
#endif
	}

VosT_Obtype
_op_manet_dispatcher_head_init (int * init_block_ptr)
	{
	FIN_MT (_op_manet_dispatcher_head_init (init_block_ptr))

	manet_dispatcher_head_state::obtype = Vos_Define_Object_Prstate ("proc state vars (manet_dispatcher_head)",
		sizeof (manet_dispatcher_head_state));
	*init_block_ptr = 0;

	FRET (manet_dispatcher_head_state::obtype)
	}

VosT_Address
_op_manet_dispatcher_head_alloc (VosT_Obtype, int)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	manet_dispatcher_head_state * ptr;
	FIN_MT (_op_manet_dispatcher_head_alloc ())

	/* New instance will have FSM handling initialized */
#if defined (VOSD_NEW_BAD_ALLOC)
	try {
		ptr = new manet_dispatcher_head_state;
	} catch (const VOSD_BAD_ALLOC &) {
		ptr = VOSC_NIL;
	}
#else
	ptr = new manet_dispatcher_head_state;
#endif
	FRET ((VosT_Address)ptr)
	}



void
_op_manet_dispatcher_head_svar (void * gen_ptr, const char * var_name, void ** var_p_ptr)
	{
	manet_dispatcher_head_state		*prs_ptr;

	FIN_MT (_op_manet_dispatcher_head_svar (gen_ptr, var_name, var_p_ptr))

	if (var_name == OPC_NIL)
		{
		*var_p_ptr = (void *)OPC_NIL;
		FOUT
		}
	prs_ptr = (manet_dispatcher_head_state *)gen_ptr;

	if (strcmp ("my_objid" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->my_objid);
		FOUT
		}
	if (strcmp ("my_node_objid" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->my_node_objid);
		FOUT
		}
	if (strcmp ("my_subnet_objid" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->my_subnet_objid);
		FOUT
		}
	if (strcmp ("local_packets_received_hndl" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->local_packets_received_hndl);
		FOUT
		}
	if (strcmp ("local_bits_received_hndl" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->local_bits_received_hndl);
		FOUT
		}
	if (strcmp ("local_delay_hndl" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->local_delay_hndl);
		FOUT
		}
	if (strcmp ("global_packets_received_hndl" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->global_packets_received_hndl);
		FOUT
		}
	if (strcmp ("global_bits_received_hndl" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->global_bits_received_hndl);
		FOUT
		}
	if (strcmp ("outstrm_to_ip_encap" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->outstrm_to_ip_encap);
		FOUT
		}
	if (strcmp ("instrm_from_ip_encap" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->instrm_from_ip_encap);
		FOUT
		}
	if (strcmp ("manet_flow_info_array" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->manet_flow_info_array);
		FOUT
		}
	if (strcmp ("higher_layer_proto_id" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->higher_layer_proto_id);
		FOUT
		}
	if (strcmp ("ip_encap_req_ici_ptr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->ip_encap_req_ici_ptr);
		FOUT
		}
	if (strcmp ("local_packets_sent_hndl" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->local_packets_sent_hndl);
		FOUT
		}
	if (strcmp ("local_bits_sent_hndl" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->local_bits_sent_hndl);
		FOUT
		}
	if (strcmp ("global_packets_sent_hndl" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->global_packets_sent_hndl);
		FOUT
		}
	if (strcmp ("global_bits_sent_hndl" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->global_bits_sent_hndl);
		FOUT
		}
	if (strcmp ("global_delay_hndl" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->global_delay_hndl);
		FOUT
		}
	if (strcmp ("iface_info_ptr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->iface_info_ptr);
		FOUT
		}
	if (strcmp ("next_pkt_interarrival" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->next_pkt_interarrival);
		FOUT
		}
	if (strcmp ("cluster_key" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->cluster_key);
		FOUT
		}
	if (strcmp ("symmetric_key" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->symmetric_key);
		FOUT
		}
	*var_p_ptr = (void *)OPC_NIL;

	FOUT
	}

