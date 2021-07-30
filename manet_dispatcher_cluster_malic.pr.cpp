/* Process model C++ form file: manet_dispatcher_cluster_malic.pr.cpp */
/* Portions of this file copyright 1986-2008 by OPNET Technologies, Inc. */



/* This variable carries the header into the object file */
const char manet_dispatcher_cluster_malic_pr_cpp [] = "MIL_3_Tfile_Hdr_ 145A 30A op_runsim 7 58F37747 58F37747 1 hp-PC hp 0 0 none none 0 0 none 0 0 0 0 0 0 0 0 1e80 8                                                                                                                                                                                                                                                                                                                                                                                                               ";
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

#include<iostream>
//new


using namespace std;
#define uchar unsigned char // 8-bit byte
#define uint unsigned long // 32-bit word


/* Transition Macros				*/
#define		SELF_INTERRUPT 		(OPC_INTRPT_SELF == intrpt_type)
#define		STREAM_INTERRUPT 	(OPC_INTRPT_STRM == intrpt_type)

////////////////////////////////////////////////////////////////////////////////

//Done by me
//msg sent from head for hash_auth
#define    auth_hash     3

//msg sent from member head hash_Nid
#define    re_hashed     4

static int *x;
// static Prg_List *  ckey;
// Prg_List* symkey;// to store key for head

//uchar sub_nid[16]={0x2b,0x7e, 0x15 ,0x16 ,0x28 ,0xae ,0xd2,0xa6,0xab,0xf7 ,0x15,0x88,0x09,0xcf,0x4f,0x3c};
 //uchar sub_nid[16]={0x00,0x01, 0x02 ,0x03 ,0x04 ,0x05 ,0x06,0x07,0x08,0x09 ,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};


//sha 256 def
//********************************************************************************

static uchar Nid[]={"72d9810a309aef0857d771be2b73c073b6108d1407811f352603eeb16158a123456789dff4aabbccddeeff"};
					
//{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"};
static uchar ophash_me[32];// output of 256 bits


#define DBL_INT_ADD(a,b,c) if (a > 0xffffffff - (c)) ++b; a += c;//? b for blocks
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))


typedef struct {
   uchar data[64];//block in bytes
   unsigned int datalen;
   unsigned int bitlen[2];
   unsigned int state[8];
} SHA256_CTX;

static unsigned int k[64] = {
   0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
   0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
   0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
   0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
   0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
   0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
   0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
   0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

//^^^^^^^^^^^^^^^^^^^*******************************************^^^^^^^^^^^^^^^^^^^^^^

//AES def


#define KE_ROTWORD(x) ( ((x) << 8) | ((x) >> 24) )




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



// def for handling msgs
 struct msg_info
	{
	int type;
	Prg_List * info;
	unsigned char info_arr[16];
	int rand[2];
	
	};



 struct comer
	{
	int id;
	bool New;
	
	};

/** Function prototypes.			**/
static void				manet_rpg_sv_init (void);
static void				manet_rpg_register_self (void);
static void				manet_rpg_sent_stats_update (double pkt_size);
static void				manet_rpg_received_stats_update (double pkt_size);
static void				manet_rpg_packet_flow_info_read (void);
static void				manet_rpg_generate_packet (void);
static void				manet_rpg_packet_destroy (Packet*	pkptr);


static void                   authen_hash(comer *c);// from head
static void 				re_hash(Objid id,Prg_List * list);// member reply auth hash to head


static void  					gen_hash();





// SHA 256 fn

static void sha256_transform(SHA256_CTX *ctx, unsigned char data[]);
static void sha256_init(SHA256_CTX *ctx);
static void sha256_update(SHA256_CTX *ctx, unsigned char data[], int len,int l);
static void sha256_final(SHA256_CTX *ctx, unsigned char hash[]);

//************************************************************************************

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
class manet_dispatcher_cluster_malic_state
	{
	private:
		/* Internal state tracking for FSM */
		FSM_SYS_STATE

	public:
		manet_dispatcher_cluster_malic_state (void);

		/* Destructor contains Termination Block */
		~manet_dispatcher_cluster_malic_state (void);

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
	//Done by me
		Prg_List *	             		cluster_key                                     ;
		Prg_List *	             		symmetric_key                                   ;
		bool	                   		misbehave                                       ;
		unsigned char	          		ophash[32]                                      ;
		int	                    		new_variable                                    ;

		/* FSM code */
		void manet_dispatcher_cluster_malic (OP_SIM_CONTEXT_ARG_OPT);
		/* Diagnostic Block */
		void _op_manet_dispatcher_cluster_malic_diag (OP_SIM_CONTEXT_ARG_OPT);

#if defined (VOSD_NEW_BAD_ALLOC)
		void * operator new (size_t) throw (VOSD_BAD_ALLOC);
#else
		void * operator new (size_t);
#endif
		void operator delete (void *);

		/* Memory management */
		static VosT_Obtype obtype;
	};

VosT_Obtype manet_dispatcher_cluster_malic_state::obtype = (VosT_Obtype)OPC_NIL;

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
//Done by me
#define cluster_key             		op_sv_ptr->cluster_key
#define symmetric_key           		op_sv_ptr->symmetric_key
#define misbehave               		op_sv_ptr->misbehave
#define ophash                  		op_sv_ptr->ophash
#define new_variable            		op_sv_ptr->new_variable

/* These macro definitions will define a local variable called	*/
/* "op_sv_ptr" in each function containing a FIN statement.	*/
/* This variable points to the state variable data structure,	*/
/* and can be used from a C debugger to display their values.	*/
#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE
#define FIN_PREAMBLE_DEC	manet_dispatcher_cluster_malic_state *op_sv_ptr;
#define FIN_PREAMBLE_CODE	\
		op_sv_ptr = ((manet_dispatcher_cluster_malic_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr));


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

void re_hash(Objid id,Prg_List * list)// member reply auth hash to head
	{
		
	Packet * pkt;
	Objid procid;
	unsigned char * ch;
	SHA256_CTX * ctx;
	msg_info * msg;
	int *x,*y;
	FIN(re_hash(<args>));
	Objid	objid         = op_id_self ();
	Objid	node_objid    = op_topo_parent (objid);
	msg=new msg_info;
	msg->info=prg_list_create();
	prg_list_init(msg->info);
	ctx=new SHA256_CTX();
	sha256_init(ctx);
	x=(int*)prg_list_access(list,0);
	y=(int*)prg_list_access(list,1);
	//cout<<"in re hash"<<node_objid<<"\n";//" "<<*x<<" "<<*y<<
   sha256_update(ctx,Nid,*x,*y+1);
   sha256_final(ctx,ophash);
	for(int i=0;i<32;i++)// copy hashed value into list
		{
		//ch=new unsigned char;
		ch=&ophash[i];
		prg_list_insert(msg->info,ch,i);
		}
		

		prg_list_insert(msg->info,x,32);
		prg_list_insert(msg->info,y,33);
		
	
		msg->type=re_hashed;
		pkt=op_pk_create(0);
		procid = op_id_from_name(id,OPC_OBJTYPE_PROC,"traf_src");
		
		op_pk_fd_set (pkt, 0, OPC_FIELD_TYPE_STRUCT, msg, sizeof(msg_info)*8,op_prg_mem_copy_create,op_prg_mem_free,sizeof(msg_info));
	
		op_pk_deliver(pkt,procid,0);
	 
	FOUT;
	
	}


		 
		
			






//^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//SHA256 fn

void sha256_transform(SHA256_CTX *ctx, unsigned char data[])
{  
   unsigned int a,b,c,d,e,f,g,h,i,j,t1,t2,m[64];
      
   for (i=0,j=0; i < 16; ++i, j += 4)//take 4 bytes
      m[i] = (data[j] << 24) | (data[j+1] << 16) | (data[j+2] << 8) | (data[j+3]);//divide into 4 bytes blocks
   for ( ; i < 64; ++i)
      m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];

   a = ctx->state[0];
   b = ctx->state[1];
   c = ctx->state[2];
   d = ctx->state[3];
   e = ctx->state[4];
   f = ctx->state[5];
   g = ctx->state[6];
   h = ctx->state[7];
   
   for (i = 0; i < 64; ++i) {
      t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
      t2 = EP0(a) + MAJ(a,b,c);
      h = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
   }
   
   ctx->state[0] += a;
   ctx->state[1] += b;
   ctx->state[2] += c;
   ctx->state[3] += d;
   ctx->state[4] += e;
   ctx->state[5] += f;
   ctx->state[6] += g;
   ctx->state[7] += h;
}  


////////////////////////////////////////////////////////////////////////////////
//1)intial hash value
void sha256_init(SHA256_CTX *ctx)
{  
   ctx->datalen = 0; 
   ctx->bitlen[0] = 0; 
   ctx->bitlen[1] = 0; 
   ctx->state[0] = 0x6a09e667;//H0
   ctx->state[1] = 0xbb67ae85;
   ctx->state[2] = 0x3c6ef372;
   ctx->state[3] = 0xa54ff53a;
   ctx->state[4] = 0x510e527f;
   ctx->state[5] = 0x9b05688c;
   ctx->state[6] = 0x1f83d9ab;
   ctx->state[7] = 0x5be0cd19;//H7
}

void sha256_update(SHA256_CTX *ctx, unsigned char data[],int s,int e)
{  

   unsigned int i;
   
   for (i=s; i < e; ++i) { 
      ctx->data[ctx->datalen] = data[i]; 
      ctx->datalen++; 
      if (ctx->datalen == 64) { 
         sha256_transform(ctx,ctx->data);
         DBL_INT_ADD(ctx->bitlen[0],ctx->bitlen[1],512); 
         ctx->datalen = 0; 
      }  
   }  
}  

void sha256_final(SHA256_CTX *ctx, unsigned char hash[])
{  
   unsigned int i; 
   
   i = ctx->datalen; 
   
   // Pad whatever data is left in the buffer. 
   if (ctx->datalen < 56) { 
      ctx->data[i++] = 0x80; 
      while (i < 56) 
         ctx->data[i++] = 0x00; 
   }  
   else { 
      ctx->data[i++] = 0x80; 
      while (i < 64) 
         ctx->data[i++] = 0x00; 
      sha256_transform(ctx,ctx->data);
      memset(ctx->data,0,56); 
   }  
   
   // Append to the padding the total message's length in bits and transform. 
   DBL_INT_ADD(ctx->bitlen[0],ctx->bitlen[1],ctx->datalen * 8);
   ctx->data[63] = ctx->bitlen[0]; 
   ctx->data[62] = ctx->bitlen[0] >> 8; 
   ctx->data[61] = ctx->bitlen[0] >> 16; 
   ctx->data[60] = ctx->bitlen[0] >> 24; 
   ctx->data[59] = ctx->bitlen[1]; 
   ctx->data[58] = ctx->bitlen[1] >> 8; 
   ctx->data[57] = ctx->bitlen[1] >> 16;  
   ctx->data[56] = ctx->bitlen[1] >> 24; 
   sha256_transform(ctx,ctx->data);
   
   // Since this implementation uses little endian byte ordering and SHA uses big endian,
   // reverse all the bytes when copying the final state to the output hash. 
   for (i=0; i < 4; ++i) { 
      hash[i]    = (ctx->state[0] >> (24-i*8)) & 0x000000ff; 
      hash[i+4]  = (ctx->state[1] >> (24-i*8)) & 0x000000ff; 
      hash[i+8]  = (ctx->state[2] >> (24-i*8)) & 0x000000ff;
      hash[i+12] = (ctx->state[3] >> (24-i*8)) & 0x000000ff;
      hash[i+16] = (ctx->state[4] >> (24-i*8)) & 0x000000ff;
      hash[i+20] = (ctx->state[5] >> (24-i*8)) & 0x000000ff;
      hash[i+24] = (ctx->state[6] >> (24-i*8)) & 0x000000ff;
      hash[i+28] = (ctx->state[7] >> (24-i*8)) & 0x000000ff;
   }  
}  


//^^^^^^^^^^^^^^^**********************************^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^


 

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
#undef misbehave
#undef ophash
#undef new_variable

/* Access from C kernel using C linkage */
extern "C"
{
	VosT_Obtype _op_manet_dispatcher_cluster_malic_init (int * init_block_ptr);
	VosT_Address _op_manet_dispatcher_cluster_malic_alloc (VosT_Obtype, int);
	void manet_dispatcher_cluster_malic (OP_SIM_CONTEXT_ARG_OPT)
		{
		((manet_dispatcher_cluster_malic_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr))->manet_dispatcher_cluster_malic (OP_SIM_CONTEXT_PTR_OPT);
		}

	void _op_manet_dispatcher_cluster_malic_svar (void *, const char *, void **);

	void _op_manet_dispatcher_cluster_malic_diag (OP_SIM_CONTEXT_ARG_OPT)
		{
		((manet_dispatcher_cluster_malic_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr))->_op_manet_dispatcher_cluster_malic_diag (OP_SIM_CONTEXT_PTR_OPT);
		}

	void _op_manet_dispatcher_cluster_malic_terminate (OP_SIM_CONTEXT_ARG_OPT)
		{
		/* The destructor is the Termination Block */
		delete (manet_dispatcher_cluster_malic_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr);
		}


} /* end of 'extern "C"' */




/* Process model interrupt handling procedure */


void
manet_dispatcher_cluster_malic_state::manet_dispatcher_cluster_malic (OP_SIM_CONTEXT_ARG_OPT)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	FIN_MT (manet_dispatcher_cluster_malic_state::manet_dispatcher_cluster_malic ());
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


		FSM_ENTER ("manet_dispatcher_cluster_malic")

		FSM_BLOCK_SWITCH
			{
			/*---------------------------------------------------------*/
			/** state (init) enter executives **/
			FSM_STATE_ENTER_UNFORCED_NOLABEL (0, "init", "manet_dispatcher_cluster_malic [init enter execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_cluster_malic [init enter execs]", state0_enter_exec)
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
				
				
				misbehave=true;	  
				
				}
				FSM_PROFILE_SECTION_OUT (state0_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (1,"manet_dispatcher_cluster_malic")


			/** state (init) exit executives **/
			FSM_STATE_EXIT_UNFORCED (0, "init", "manet_dispatcher_cluster_malic [init exit execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_cluster_malic [init exit execs]", state0_exit_exec)
				{
				
				}
				FSM_PROFILE_SECTION_OUT (state0_exit_exec)


			/** state (init) transition processing **/
			FSM_TRANSIT_FORCE (2, state2_enter_exec, ;, "default", "", "init", "wait", "tr_31", "manet_dispatcher_cluster_malic [init -> wait : default / ]")
				/*---------------------------------------------------------*/



			/** state (discover) enter executives **/
			FSM_STATE_ENTER_UNFORCED (1, "discover", state1_enter_exec, "manet_dispatcher_cluster_malic [discover enter execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_cluster_malic [discover enter execs]", state1_enter_exec)
				{
				/* Schedule a self interrupt, that will indicate the completion of		*/
				/* lower layer initializations. We will perform the discovery process	*/
				/* following the delivery of this interrupt, i.e. in the exit execs of	*/
				/* this state.															*/
				op_intrpt_schedule_self (op_sim_time (), 0);
				}
				FSM_PROFILE_SECTION_OUT (state1_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (3,"manet_dispatcher_cluster_malic")


			/** state (discover) exit executives **/
			FSM_STATE_EXIT_UNFORCED (1, "discover", "manet_dispatcher_cluster_malic [discover exit execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_cluster_malic [discover exit execs]", state1_exit_exec)
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
			FSM_TRANSIT_FORCE (4, state4_enter_exec, ;, "default", "", "discover", "wait_2", "tr_40", "manet_dispatcher_cluster_malic [discover -> wait_2 : default / ]")
				/*---------------------------------------------------------*/



			/** state (wait) enter executives **/
			FSM_STATE_ENTER_UNFORCED (2, "wait", state2_enter_exec, "manet_dispatcher_cluster_malic [wait enter execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_cluster_malic [wait enter execs]", state2_enter_exec)
				{
				/* Wait for one more wave of interrupts to gurantee that lower layers	*/
				/* will have finalized their address resolution when we query for the	*/
				/* address (and other) information in the exit execs of discover state.	*/
				
				op_intrpt_schedule_self (op_sim_time (), 0);
				}
				FSM_PROFILE_SECTION_OUT (state2_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (5,"manet_dispatcher_cluster_malic")


			/** state (wait) exit executives **/
			FSM_STATE_EXIT_UNFORCED (2, "wait", "manet_dispatcher_cluster_malic [wait exit execs]")


			/** state (wait) transition processing **/
			FSM_TRANSIT_FORCE (5, state5_enter_exec, ;, "default", "", "wait", "wait_0", "tr_37", "manet_dispatcher_cluster_malic [wait -> wait_0 : default / ]")
				/*---------------------------------------------------------*/



			/** state (dispatch) enter executives **/
			FSM_STATE_ENTER_UNFORCED (3, "dispatch", state3_enter_exec, "manet_dispatcher_cluster_malic [dispatch enter execs]")

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (7,"manet_dispatcher_cluster_malic")


			/** state (dispatch) exit executives **/
			FSM_STATE_EXIT_UNFORCED (3, "dispatch", "manet_dispatcher_cluster_malic [dispatch exit execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_cluster_malic [dispatch exit execs]", state3_exit_exec)
				{
				/* Get the interrupt type. This will be used to determine	*/
				/* whether this is a self interrupt to generate a packet or	*/
				/* a stream interrupt from ip_encap.						*/
				
				int  x;
				
				
				Packet * rcvd_pkt=OPC_NIL;
				Objid src_objid, src_node_objid;
				Objid	objid         = op_id_self ();
				Objid	node_objid    = op_topo_parent (objid);
				//unsigned char * ch;
				
				/*op_ima_obj_attr_get_toggle(node_objid,"condition",&x);
				if(x==1)
				{
				op_ima_obj_attr_set_toggle(node_objid,"condition",0);
				}
				else
				{
				op_ima_obj_attr_set_toggle(node_objid,"condition",1);	
				cout<<"enable"<<"\n";
				}*/
				msg_info * msg=new msg_info();
				
				intrpt_type = op_intrpt_type ();
				if (intrpt_type==OPC_INTRPT_STRM)
					{
					rcvd_pkt=op_pk_get (op_intrpt_strm ());
				
						x=op_pk_fd_max_index(rcvd_pkt);
					
						if(x<0)
							
						manet_rpg_packet_destroy(rcvd_pkt);
						
						else
							{
							
							
							op_pk_fd_get(rcvd_pkt,0,&msg);
							switch(msg->type)
							{
							
							
							case auth_hash:// member received auth message
								//cout<<op_sim_time()<<" "<<"auht"<<"\n";
							 src_objid = op_pk_creation_mod_get (rcvd_pkt);
							 src_node_objid = op_topo_parent (src_objid);
							re_hash(src_node_objid,msg->info);
					
							//cout<<src_node_objid<<"\n";
				
							break;
				
							
						
							
							default:
							break;
					
							}
							
							//delete msg;					
							/* Destroy the received packet.	*/				
							op_pk_destroy (rcvd_pkt);
							
							}
					
					
							
					
					}
					
					
				
				}
				FSM_PROFILE_SECTION_OUT (state3_exit_exec)


			/** state (dispatch) transition processing **/
			FSM_PROFILE_SECTION_IN ("manet_dispatcher_cluster_malic [dispatch trans conditions]", state3_trans_conds)
			FSM_INIT_COND (SELF_INTERRUPT)
			FSM_DFLT_COND
			FSM_TEST_LOGIC ("dispatch")
			FSM_PROFILE_SECTION_OUT (state3_trans_conds)

			FSM_TRANSIT_SWITCH
				{
				FSM_CASE_TRANSIT (0, 3, state3_enter_exec, manet_rpg_generate_packet ();, "SELF_INTERRUPT", "manet_rpg_generate_packet ()", "dispatch", "dispatch", "tr_30", "manet_dispatcher_cluster_malic [dispatch -> dispatch : SELF_INTERRUPT / manet_rpg_generate_packet ()]")
				FSM_CASE_TRANSIT (1, 3, state3_enter_exec, ;, "default", "", "dispatch", "dispatch", "tr_33", "manet_dispatcher_cluster_malic [dispatch -> dispatch : default / ]")
				}
				/*---------------------------------------------------------*/



			/** state (wait_2) enter executives **/
			FSM_STATE_ENTER_UNFORCED (4, "wait_2", state4_enter_exec, "manet_dispatcher_cluster_malic [wait_2 enter execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_cluster_malic [wait_2 enter execs]", state4_enter_exec)
				{
				/** Wait so that all nodes can register their		**/
				/** own addresses in the global list of possible	**/
				/** IP destinations.								**/
				op_intrpt_schedule_self (op_sim_time (), 0);
				
				
				//send_pkt();
				}
				FSM_PROFILE_SECTION_OUT (state4_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (9,"manet_dispatcher_cluster_malic")


			/** state (wait_2) exit executives **/
			FSM_STATE_EXIT_UNFORCED (4, "wait_2", "manet_dispatcher_cluster_malic [wait_2 exit execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_cluster_malic [wait_2 exit execs]", state4_exit_exec)
				{
				/* Read in the traffic flow information	*/
				manet_rpg_packet_flow_info_read ();
				}
				FSM_PROFILE_SECTION_OUT (state4_exit_exec)


			/** state (wait_2) transition processing **/
			FSM_TRANSIT_FORCE (3, state3_enter_exec, ;, "default", "", "wait_2", "dispatch", "tr_41", "manet_dispatcher_cluster_malic [wait_2 -> dispatch : default / ]")
				/*---------------------------------------------------------*/



			/** state (wait_0) enter executives **/
			FSM_STATE_ENTER_UNFORCED (5, "wait_0", state5_enter_exec, "manet_dispatcher_cluster_malic [wait_0 enter execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_cluster_malic [wait_0 enter execs]", state5_enter_exec)
				{
				/** Wait so that all nodes can register their		**/
				/** own addresses in the global list of possible	**/
				/** IP destinations.								**/
				op_intrpt_schedule_self (op_sim_time (), 0);
				}
				FSM_PROFILE_SECTION_OUT (state5_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (11,"manet_dispatcher_cluster_malic")


			/** state (wait_0) exit executives **/
			FSM_STATE_EXIT_UNFORCED (5, "wait_0", "manet_dispatcher_cluster_malic [wait_0 exit execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_cluster_malic [wait_0 exit execs]", state5_exit_exec)
				{
				
				}
				FSM_PROFILE_SECTION_OUT (state5_exit_exec)


			/** state (wait_0) transition processing **/
			FSM_TRANSIT_FORCE (6, state6_enter_exec, ;, "default", "", "wait_0", "wait_1", "tr_39", "manet_dispatcher_cluster_malic [wait_0 -> wait_1 : default / ]")
				/*---------------------------------------------------------*/



			/** state (wait_1) enter executives **/
			FSM_STATE_ENTER_UNFORCED (6, "wait_1", state6_enter_exec, "manet_dispatcher_cluster_malic [wait_1 enter execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_cluster_malic [wait_1 enter execs]", state6_enter_exec)
				{
				/** Wait so that all nodes can register their		**/
				/** own addresses in the global list of possible	**/
				/** IP destinations.								**/
				op_intrpt_schedule_self (op_sim_time (), 0);
				}
				FSM_PROFILE_SECTION_OUT (state6_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (13,"manet_dispatcher_cluster_malic")


			/** state (wait_1) exit executives **/
			FSM_STATE_EXIT_UNFORCED (6, "wait_1", "manet_dispatcher_cluster_malic [wait_1 exit execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_cluster_malic [wait_1 exit execs]", state6_exit_exec)
				{
				
				}
				FSM_PROFILE_SECTION_OUT (state6_exit_exec)


			/** state (wait_1) transition processing **/
			FSM_TRANSIT_FORCE (1, state1_enter_exec, ;, "default", "", "wait_1", "discover", "tr_32", "manet_dispatcher_cluster_malic [wait_1 -> discover : default / ]")
				/*---------------------------------------------------------*/



			}


		FSM_EXIT (0,"manet_dispatcher_cluster_malic")
		}
	catch (...)
		{
		Vos_Error_Print (VOSC_ERROR_ABORT,
			(const char *)VOSC_NIL,
			"Unhandled C++ exception in process model (manet_dispatcher_cluster_malic)",
			(const char *)VOSC_NIL, (const char *)VOSC_NIL);
		}
	}




void
manet_dispatcher_cluster_malic_state::_op_manet_dispatcher_cluster_malic_diag (OP_SIM_CONTEXT_ARG_OPT)
	{
	/* No Diagnostic Block */
	}

void
manet_dispatcher_cluster_malic_state::operator delete (void* ptr)
	{
	FIN (manet_dispatcher_cluster_malic_state::operator delete (ptr));
	Vos_Poolmem_Dealloc (ptr);
	FOUT
	}

manet_dispatcher_cluster_malic_state::~manet_dispatcher_cluster_malic_state (void)
	{

	FIN (manet_dispatcher_cluster_malic_state::~manet_dispatcher_cluster_malic_state ())


	/* No Termination Block */


	FOUT
	}


#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE

#define FIN_PREAMBLE_DEC
#define FIN_PREAMBLE_CODE

void *
manet_dispatcher_cluster_malic_state::operator new (size_t)
#if defined (VOSD_NEW_BAD_ALLOC)
		throw (VOSD_BAD_ALLOC)
#endif
	{
	void * new_ptr;

	FIN_MT (manet_dispatcher_cluster_malic_state::operator new ());

	new_ptr = Vos_Alloc_Object (manet_dispatcher_cluster_malic_state::obtype);
#if defined (VOSD_NEW_BAD_ALLOC)
	if (new_ptr == VOSC_NIL) throw VOSD_BAD_ALLOC();
#endif
	FRET (new_ptr)
	}

/* State constructor initializes FSM handling */
/* by setting the initial state to the first */
/* block of code to enter. */

manet_dispatcher_cluster_malic_state::manet_dispatcher_cluster_malic_state (void) :
		_op_current_block (0)
	{
#if defined (OPD_ALLOW_ODB)
		_op_current_state = "manet_dispatcher_cluster_malic [init enter execs]";
#endif
	}

VosT_Obtype
_op_manet_dispatcher_cluster_malic_init (int * init_block_ptr)
	{
	FIN_MT (_op_manet_dispatcher_cluster_malic_init (init_block_ptr))

	manet_dispatcher_cluster_malic_state::obtype = Vos_Define_Object_Prstate ("proc state vars (manet_dispatcher_cluster_malic)",
		sizeof (manet_dispatcher_cluster_malic_state));
	*init_block_ptr = 0;

	FRET (manet_dispatcher_cluster_malic_state::obtype)
	}

VosT_Address
_op_manet_dispatcher_cluster_malic_alloc (VosT_Obtype, int)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	manet_dispatcher_cluster_malic_state * ptr;
	FIN_MT (_op_manet_dispatcher_cluster_malic_alloc ())

	/* New instance will have FSM handling initialized */
#if defined (VOSD_NEW_BAD_ALLOC)
	try {
		ptr = new manet_dispatcher_cluster_malic_state;
	} catch (const VOSD_BAD_ALLOC &) {
		ptr = VOSC_NIL;
	}
#else
	ptr = new manet_dispatcher_cluster_malic_state;
#endif
	FRET ((VosT_Address)ptr)
	}



void
_op_manet_dispatcher_cluster_malic_svar (void * gen_ptr, const char * var_name, void ** var_p_ptr)
	{
	manet_dispatcher_cluster_malic_state		*prs_ptr;

	FIN_MT (_op_manet_dispatcher_cluster_malic_svar (gen_ptr, var_name, var_p_ptr))

	if (var_name == OPC_NIL)
		{
		*var_p_ptr = (void *)OPC_NIL;
		FOUT
		}
	prs_ptr = (manet_dispatcher_cluster_malic_state *)gen_ptr;

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
	if (strcmp ("misbehave" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->misbehave);
		FOUT
		}
	if (strcmp ("ophash" , var_name) == 0)
		{
		*var_p_ptr = (void *) (prs_ptr->ophash);
		FOUT
		}
	if (strcmp ("new_variable" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->new_variable);
		FOUT
		}
	*var_p_ptr = (void *)OPC_NIL;

	FOUT
	}

