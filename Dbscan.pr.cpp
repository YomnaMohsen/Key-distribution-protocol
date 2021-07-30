/* Process model C++ form file: recorder.pr.cpp */
/* Portions of this file copyright 1986-2008 by OPNET Technologies, Inc. */



/* This variable carries the header into the object file */
const char recorder_pr_cpp [] = "MIL_3_Tfile_Hdr_ 145A 30A modeler 7 57CAC52A 57CAC52A 1 hp-PC hp 0 0 none none 0 0 none 0 0 0 0 0 0 0 0 1e80 8                                                                                                                                                                                                                                                                                                                                                                                                                 ";
#include <string.h>



/* OPNET system definitions */
#include <opnet.h>



/* Header Block */

#include<iostream>
#include<math.h>
#include <prg_string_funcs.h>
#include <oms_pr.h>

using namespace std;


#define		Check   2902
#define		Start   2901
#define    Do_Check (intrpt_code==Check)
#define    Do_Start (intrpt_code==Start)
#define    head      1
#define    malc      8
#define    recev      9
#define    over_head      10
#define   comer_msg      11
int counter=0,row=0;
int size;
int* node_id;
PrgT_List * dist_list;
PrgT_List * global_list;

PrgT_List * cluster_list;
PrgT_List * noise_list;
int check;

const int Noise=-1;
const int minpnt=3;
const int Unclassified =0;
const double eps=75.0;
int total_size=0;
int cid=1;
int index;
int id_iter=0;
int recev_list[24];
int  overh_list[24];
int  comer_list[24];
double avail,success;
int diff1,diff2;
int noise_count=0,mem_count=0,overh=0,over_h;
int head_count=0,expec,actual_comer=0,comer_count=0;
int ncount=0;

struct coord
{
double xpos;
double ypos;
int Clusterid;
int Nodeid;
bool change;
bool New_comer;
int pos;
int counter;

};

struct msg_info
{ 
	int type;
	Prg_List * info;
	

};


struct comer
	{
	int id;
	bool New;
	int counter;// to select head with max neigh
	
	}
;




unsigned char file[24][16];
coord * temp;
//{0x00, 0x11 ,0x22 ,0x33,0x44 ,0x55 ,0x66 ,0x77,0x88 ,0x99,0xaa,0xbb,0xcc ,0xdd,0xee,0xff};
//// 128 bits
////={0x00,0x01, 0x02 ,0x03 ,0x04 ,0x05 ,0x06,0x07,0x08,0x09 ,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};;
//unsigned char ckey[16]={0x32,0x43 ,0xf6,0xa8,0x88,0x5a ,0x30 ,0x8d ,0x31 ,0x31 ,0x98 ,0xa2 ,0xe0 ,0x37 ,0x07 ,0x34};
List * list;
//unsigned char ckey[16],symkey[16];
Prg_List * word_list_ptr;
//dbscan functions

bool ExpandCluster(PrgT_List * list,coord* store,int id);
void create_list();
void add_postions();
double eculid_dist(coord* point ,coord* orgp);
PrgT_List* region_query(PrgT_List* list,coord * store);
void Recheck_cluster(PrgT_List * list);
void scan_noise(PrgT_List * list);
int elect_head(PrgT_List * list);
int elect_head_maxn(PrgT_List * list);

void partition(PrgT_List * list);
void send_head(int id,Prg_List * list);//send announce to cluster head
void reset_comer(Prg_List * list);
void convert_hex(PrgT_List* list,unsigned char arr[]);//
void read_file(int count);
void reset_malcious(Prg_List * list);
void form_cluster(PrgT_List * noise_list);
PrgT_List* region_query_index(PrgT_List* list,coord * store);

void check_part(Prg_List * list);
bool check_node(coord *t);
bool check_noiselist(Prg_List * list);
int check_neigh(coord* s,Prg_List * list);
void store_recev(Prg_List * list);
void store_comer(Prg_List * list);
void change_stat();

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
class recorder_state
	{
	private:
		/* Internal state tracking for FSM */
		FSM_SYS_STATE

	public:
		recorder_state (void);

		/* Destructor contains Termination Block */
		~recorder_state (void);

		/* State Variables */
		Stathandle	             		bits_rcvd_stathandle                            ;
		Stathandle	             		bitssec_rcvd_stathandle                         ;
		Stathandle	             		pkts_rcvd_stathandle                            ;
		Stathandle	             		pktssec_rcvd_stathandle                         ;
		Stathandle	             		ete_delay_stathandle                            ;
		Stathandle	             		bits_rcvd_gstathandle                           ;
		Stathandle	             		bitssec_rcvd_gstathandle                        ;
		Stathandle	             		pkts_rcvd_gstathandle                           ;
		Stathandle	             		pktssec_rcvd_gstathandle                        ;
		Stathandle	             		ete_delay_gstathandle                           ;
		double	                 		xcoord                                          ;
		double	                 		ycoord                                          ;
		Objid	                  		my_id                                           ;
		char	                   		proc_name[20]                                   ;
		OmsT_Pr_Handle	         		own_process_record_handle                       ;
		double	                 		start_time                                      ;
		double	                 		stop_time                                       ;
		Stathandle	             		avail_per_stathandle                            ;
		Stathandle	             		head_per_stathandle                             ;
		Stathandle	             		noise_per_stathandle                            ;
		Stathandle	             		mem_per_stathandle                              ;
		Stathandle	             		overhead_handle                                 ;
		Stathandle	             		success_handle                                  ;

		/* FSM code */
		void recorder (OP_SIM_CONTEXT_ARG_OPT);
		/* Diagnostic Block */
		void _op_recorder_diag (OP_SIM_CONTEXT_ARG_OPT);

#if defined (VOSD_NEW_BAD_ALLOC)
		void * operator new (size_t) throw (VOSD_BAD_ALLOC);
#else
		void * operator new (size_t);
#endif
		void operator delete (void *);

		/* Memory management */
		static VosT_Obtype obtype;
	};

VosT_Obtype recorder_state::obtype = (VosT_Obtype)OPC_NIL;

#define bits_rcvd_stathandle    		op_sv_ptr->bits_rcvd_stathandle
#define bitssec_rcvd_stathandle 		op_sv_ptr->bitssec_rcvd_stathandle
#define pkts_rcvd_stathandle    		op_sv_ptr->pkts_rcvd_stathandle
#define pktssec_rcvd_stathandle 		op_sv_ptr->pktssec_rcvd_stathandle
#define ete_delay_stathandle    		op_sv_ptr->ete_delay_stathandle
#define bits_rcvd_gstathandle   		op_sv_ptr->bits_rcvd_gstathandle
#define bitssec_rcvd_gstathandle		op_sv_ptr->bitssec_rcvd_gstathandle
#define pkts_rcvd_gstathandle   		op_sv_ptr->pkts_rcvd_gstathandle
#define pktssec_rcvd_gstathandle		op_sv_ptr->pktssec_rcvd_gstathandle
#define ete_delay_gstathandle   		op_sv_ptr->ete_delay_gstathandle
#define xcoord                  		op_sv_ptr->xcoord
#define ycoord                  		op_sv_ptr->ycoord
#define my_id                   		op_sv_ptr->my_id
#define proc_name               		op_sv_ptr->proc_name
#define own_process_record_handle		op_sv_ptr->own_process_record_handle
#define start_time              		op_sv_ptr->start_time
#define stop_time               		op_sv_ptr->stop_time
#define avail_per_stathandle    		op_sv_ptr->avail_per_stathandle
#define head_per_stathandle     		op_sv_ptr->head_per_stathandle
#define noise_per_stathandle    		op_sv_ptr->noise_per_stathandle
#define mem_per_stathandle      		op_sv_ptr->mem_per_stathandle
#define overhead_handle         		op_sv_ptr->overhead_handle
#define success_handle          		op_sv_ptr->success_handle

/* These macro definitions will define a local variable called	*/
/* "op_sv_ptr" in each function containing a FIN statement.	*/
/* This variable points to the state variable data structure,	*/
/* and can be used from a C debugger to display their values.	*/
#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE
#define FIN_PREAMBLE_DEC	recorder_state *op_sv_ptr;
#define FIN_PREAMBLE_CODE	\
		op_sv_ptr = ((recorder_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr));


/* Function Block */

#if !defined (VOSD_NO_FIN)
enum { _op_block_origin = __LINE__ + 2};
#endif

void create_list()
	{

	global_list=prg_list_create();
	prg_list_init (global_list);
	//cout<<op_topo_object_count(OPC_OBJTYPE_NODE_MOB)<<"\n";
	for (int i = 0; i< op_topo_object_count(OPC_OBJTYPE_NODE_MOB); i++)
		{
		node_id=new int;
		*node_id = op_topo_object(OPC_OBJTYPE_NODE_MOB,i);
		prg_list_insert (global_list,node_id,i);
		
			
		}
	}


void add_postions()
{
	
	coord* store;
	dist_list=prg_list_create();
	prg_list_init (dist_list);
	
	for (int j = 0; j<prg_list_size(global_list); j++)
		{	
		
		node_id=(int *)prg_list_access(global_list,j);
		store=new coord();
		
		op_ima_obj_attr_get_dbl(*node_id, "x position", &store->xpos);	
		op_ima_obj_attr_get_dbl(*node_id, "y position", &store->ypos);
		store->Clusterid=0;
		store->Nodeid=*node_id;
		store->change=false;
		store->New_comer=false;
		store->pos=0;// to determine poistion of node in cluster list
		store->counter=0;// to select head based on neighbors number

		prg_list_insert (dist_list,store,j);
		}
	
/*	for (int j = 0; j< prg_list_size(dist_list); j++)
		{
		store=(coord *)prg_list_access(dist_list,j);
		if(store->Nodeid==2)
		cout<<"in dist "<<store->xpos<<" "<<store->ypos<<"\n";
		}
	cout<<"-----------------------------------"<<"\n";*/
		
	
}

int compare_pos(const void * s1,const void * s2)
	{
		coord * store1=(coord *)s1;
		coord * store2=(coord *)s2;
	
		if(store1->pos<store2->pos)
			return 1;
		else if(store1->pos>store2->pos)
			return -1;
		else
			return 0;
	}

int compare (const void * s1,const void * s2)
	{
		coord * store1=(coord *)s1;
		coord * store2=(coord *)s2;
	
		if(store1->Clusterid<store2->Clusterid)
			return 1;
		else if(store1->Clusterid>store2->Clusterid)
			return -1;
		else
			return 0;
	}


bool comp_eq(Prg_List * list,coord *s)
	{
	
	bool equal=false;
	for(int i=0;i<prg_list_size(list);i++)
		{
		coord * t=(coord *)prg_list_access(list,i);
		if(s->Clusterid==t->Clusterid)
			{
			equal =true;
			break;
			}
		else 
		 continue;
		}
	return equal;
	}



void find_clusters()
{


	coord* store;
	cluster_list=prg_list_create();
	prg_list_init (cluster_list);
	
	for (int i = 0; i< prg_list_size(dist_list); i++)
		{
			
			store=(coord *)prg_list_access(dist_list,i);
			if(store->Clusterid==Unclassified)
				{
				if(ExpandCluster(dist_list,store,cid))
					cid++;
		
				}
			
		
		}
	

		for (int i = 0; i< prg_list_size(dist_list); i++)
		{		
		coord *temp=(coord *)prg_list_access(dist_list,i);
		prg_list_insert_sorted(cluster_list,temp,compare);
		}
		
		/*for ( int i = 0; i< prg_list_size(cluster_list); i++)
		{		
		coord *temp=(coord *)prg_list_access(cluster_list,i);
		if(temp->Nodeid==2)
			{
			cout<<temp->counter;
			break;
		
			}
		}*/
	
		
}

bool ExpandCluster(PrgT_List * list,coord * store,int cid)
	{

		PrgT_List *seeds;
		PrgT_List *result;
		coord* current;
		seeds=region_query(list,store);
		
		if(prg_list_size(seeds)<minpnt)
			{
			store->Clusterid=Noise;
			store->counter=prg_list_size(seeds)-1;
			return false;
			}	
			
		else
			{
			
			store->counter=prg_list_size(seeds)-1;
			for(int i=0;i<prg_list_size(seeds);i++)
				{
					
					store=(coord*)prg_list_access(seeds,i);
					
					//if(store->Clusterid==Unclassified)//point remains in the first cluster
					store->Clusterid=cid;
				}
			
			
			prg_list_remove(seeds,index);//remove store
			
				
				while(prg_list_size(seeds)>0)
					{
					
						current=(coord*)prg_list_access(seeds,PRGC_LISTPOS_HEAD);
						/*if(current->Clusterid<cid)// region query for node in c 1 neighbor to c2
							{
							
							cout<<"small "<<"\n";
							prg_list_remove(seeds,PRGC_LISTPOS_HEAD);//remove store
							continue;
							
							}*/
						
						
						result=region_query(list,current);
						
						if(prg_list_size(result)>=minpnt)
							{
							
							current->counter=prg_list_size(result)-1;
							//cout<<"cluster"<<cid<<"\n";
								for(int j=0;j<prg_list_size(result);j++)
									{
									coord* resp=(coord*)prg_list_access(result,j);
									
									if(resp->Clusterid==Unclassified||resp->Clusterid==Noise)
									{
									
									
									if(resp->Clusterid==Unclassified) 
										
										{
										prg_list_insert(seeds,resp,PRGC_LISTPOS_TAIL);
										}
									
										resp->Clusterid=cid;
										
									}//end if
											
									}//end for
									
								}// end if
						
						//else 
							//cout<<"in expand"<<current->Clusterid<<" "<<current->Nodeid<<" "<<prg_list_size(result)<<"\n";
						
					
						//delete current
						prg_list_remove(seeds,PRGC_LISTPOS_HEAD);
						
					}//end while
				
				
				}//end else
		return true;
	
		}//end fn

double eculid_dist(coord* point ,coord* orgp)
	{
		double dist=sqrt(pow(point->xpos-orgp->xpos,2)+pow(point->ypos-orgp->ypos,2));
		return dist;
	
	}




PrgT_List* region_query(PrgT_List* list,coord*  store)
{

	PrgT_List* region;

	int j=0;
	
	region=prg_list_create();
	prg_list_init (region);

	for(int i=0;i<prg_list_size(list);i++)
		{
			coord * s=(coord *)prg_list_access(list,i);
			if(eculid_dist(s,store)<=eps)
				{
					prg_list_insert(region,s,j);
					j++;
					if(eculid_dist(s,store)==0)
						index=j-1;
						
				}
			
		}
	
	
	return region;

}



PrgT_List* region_query_index(PrgT_List* list,coord*  store)
{
	//returnn neighbors with their poistions in the cluster list
	PrgT_List* region;
	int j=0;
	int temp;
	region=prg_list_create();
	prg_list_init (region);
	for(int i=0;i<prg_list_size(list);i++)
		{
			coord * s=(coord *)prg_list_access(list,i);
			if(eculid_dist(s,store)<=eps)
				
				{
				s->pos=i;
				//cout<<s->Nodeid<<"\n";
					prg_list_insert(region,s,j);
					temp=j;
					//prg_list_insert(region,pos,j+1);//insert poistion of neighbors in cluster list
					j++;
					if(eculid_dist(s,store)==0)
						index=temp;
						
				}
			
		}
	
	/*cout<<"in region_query"<<index<<"\n";
	for(int i=0;i<prg_list_size(region);i+=2)
	{
	coord * u=(coord *)prg_list_access(region,i);
	int * k=(int *)prg_list_access(region,i+1);
	cout<<u->Nodeid<<" "<<*k<<"\n";
	}*/
	
	return region;

}



void Recheck_cluster(PrgT_List *list)
{
bool noise=false,large=false,found=false;
int id,num=0;
int noise_iter=0;
int j=0;

for (int i = 0; i< prg_list_size(cluster_list); i++)
	{
	
		temp=(coord *)prg_list_access(cluster_list,i);
		if(temp->Clusterid==Noise)//scan for noise
			{
			
				ncount++;
				continue;
			}
		else
		{
			
		if(temp->change)
			{
			temp->change=false;//change to visited
			PrgT_List * res=region_query(cluster_list,temp);
			prg_list_remove(res,index);//remove temp node;	
			
			if(prg_list_size(res)==0)		
			{
			temp->Clusterid=Noise;
			temp->counter=0;
			ncount++;
			prg_list_remove(cluster_list,i);
			prg_list_insert_sorted(cluster_list,temp,compare);

			continue;
			}//3rd end if
		
	
						while(j<prg_list_size(res))
					{
					
					coord * result=(coord *)prg_list_access(res,j);
					if(result->Clusterid!=Noise)//and unchanged or changed
						{
								
								if(noise_iter+1>=minpnt)
									noise =true;
								else
								noise=false;


								/*if(!comp_eq(res,temp))// if we donot find the same cluster id in the list
								id=result->Clusterid;
								else
									found=true;*/
									
									break;	
						}
						
						else
							{
							//if all neighbors are noise then node become noise 
								noise=true;
								noise_iter++;
								
								
							}
							j++;
						}//end while
			
					if(noise)
					{
					
					temp->Clusterid=Noise;
					noise=false;
					
					ncount++;
					
					prg_list_remove(cluster_list,i);
					//i--;
					prg_list_insert_sorted(cluster_list,temp,compare);
					}
					
					else
					{// not noise
					
					id=check_neigh(temp,res);
					
					//if(!found)
						{
						if(id>temp->Clusterid||id<temp->Clusterid)
							{
							//visited
							if(id>temp->Clusterid)	
								
							large=true;
								
								temp->Clusterid=id;// new comer for cluster
								temp->New_comer=true;
								prg_list_remove(cluster_list,i);
								
								if(large)
									i--;
								
								prg_list_insert_sorted(cluster_list,temp,compare);
							
								}
						
						
						}
					}
					large=false;
					j=0;
					noise_iter=0;
					
		}//end 2nd if(changed)
		else
		continue;
		}//end lst if(not noise)		
			
}//end for


}


void scan_noise(PrgT_List * list)// scan for changed noise
{

	int j=0,i=0,k=0,c=0;// to count number of noise nodes joined another cluster
	coord* temp;
	
	while(j<ncount)	
	{
	temp=(coord * )prg_list_access(cluster_list,i);
	
	i++;
	j++;
	if(!temp->change&&temp->Clusterid!=Noise)
		{
		//cout<<"node not changed"<<temp->Nodeid<<" "<<temp->Clusterid<<"\n";
		continue;
		}
	temp->change=false;
	//cout<<"n_i d"<<temp->Nodeid<<" "<<temp->Clusterid<<"\n";
		
		PrgT_List * curr=region_query_index(cluster_list,temp);
	
		prg_list_remove(curr,index);
		
	
		if(prg_list_size(curr)==0)// there is no neigh for noise point
			{
			//cout<<"node noise "<<temp->Nodeid<<" "<<temp->Clusterid<<"\n";
			temp->counter=0;
			continue;
			}
	
		while(k<prg_list_size(curr))
		{
		
		coord * cur=(coord * )prg_list_access(curr,k);
		
		if(cur->Clusterid!=Noise)
			{
			
				
			temp->Clusterid=check_neigh(temp,curr);
			
			//cout<<"changed "<<temp->Nodeid<<" "<<temp->Clusterid<<"\n";
			temp->New_comer=true;
			prg_list_remove(cluster_list,i-1);
			i--;
			prg_list_insert_sorted(cluster_list,temp,compare);// new comer for cluster
			break;
			}	
		
		else//and unchanged
		{
		
			prg_list_insert_sorted(noise_list,cur,compare_pos);//if point has noise neighborS only 
															//it can form new cluster
			if(prg_list_size(noise_list)+1>=minpnt&&(!temp->New_comer)&&(check_node(temp)))// may noise points reach minpnts and @ same time there is 
			{
			
			if(check_noiselist(noise_list))
			{
			
			temp->counter=prg_list_size(noise_list);
			for ( int h = 0; h< prg_list_size(noise_list); h++)
			{		
			coord *t=(coord *)prg_list_access(noise_list,h);
			if(t->pos-temp->pos<1)//before temp in cluster list
				i--;	
			}
			
			prg_list_insert_sorted(noise_list,temp,compare_pos);// insert noise point in noise list to know its pos in cluster_list
			form_cluster(noise_list);//another neigh point in other cluster noise point joins it
			i--;
				
			
			break;
		
			}//end  if
			
			}//end if
			
		}
		
				
	k++;
	}//while
	
	
		k=0;
	

	
if(prg_list_size(noise_list)!=0)
	{
	prg_list_free(noise_list);
	prg_list_init(noise_list);
	
	}
			
	}//end first while
											
}



int elect_head(Prg_List* list)
	
{
	int min_head=100,pos;
	comer *c;
	
	Objid procid;
	bool* flag;
	
	for(int i=0;i<prg_list_size(list);i++)
		{
	 
		
		
		c=(comer *)prg_list_access(list,i);
		cout<<"id"<<c->id<<" "<<c->counter<<" "<<c->New<<"\n";
		procid = op_id_from_name(c->id,OPC_OBJTYPE_PROC,"traf_src");
		flag=(bool *)op_ima_obj_svar_get(procid,"misbehave");
		
		
		 	if((!c->New)&&(!(*flag)))
				{
				if(c->id<min_head)
				{
				min_head=c->id;
				//cout<<c->id<<" "<<c->counter<<"\n";
				pos=i;
				
				}
				}

		 }
	cout<<"min"<<min_head<<"\n";
	

	prg_list_remove(list,pos);// remove head id
	
	/*cout<<"size"<<prg_list_size(l)<<"\n";
	if(min_head==2)
	{
		for(int i=0;i<prg_list_size(list);i++)
		{
		c=(comer *)prg_list_access(list,i);
		//cout<<c->id<<"\n";
		}
	}*/
		
	send_head(min_head,list);
	return min_head;

	
}

int elect_head_maxn(Prg_List* list)
	
{
	int max_count=-1,pos,id;
	comer *c;
	
	Objid procid;
	bool* flag;
	for(int i=0;i<prg_list_size(list);i++)
		{
	 
		
		c=(comer *)prg_list_access(list,i);
		
		//cout<<"count"<<c->counter<<" "<<c->id<<"\n";	
	procid = op_id_from_name(c->id,OPC_OBJTYPE_PROC,"traf_src");
	flag=(bool *)op_ima_obj_svar_get(procid,"misbehave");
		
		
		 	if((c->counter>max_count)&&(!c->New)&&(!(*flag)))
				{
				
				max_count=c->counter;
				pos=i;
				id=c->id;
				cout<<c->id<<" "<<c->counter<<"\n";
				
				}

		 }

	//cout<<"max"<<id<<" "<<max_count<<"\n";
	prg_list_remove(list,pos);// remove head id
		
	send_head(id,list);
	
	return id;

	
}


void partition(Prg_List * list)
	{
	//1)divide cluster_list into partitions and insert each partition in list and call
	//elect_head
	//2) insert into partition list 
	//a) sym and clus key
	//b)comer struct which consists of node id and status new comer or not
//	(comer struct)
	
	int intial;
	int i=0, j=0;
	coord * temp;
	comer * c;

	Prg_List*	part_list=prg_list_create();
	prg_list_init(part_list);
	FIN (partition(<args>));

		
	temp=(coord *)prg_list_access(list,i);//skip noise
	
		while(temp->Clusterid==Noise)
			{
			i++;
			noise_count++;
			temp=(coord *)prg_list_access(list,i);
			
		 	continue;	
			}
	
	

op_stat_write(noise_per_stathandle ,noise_count);



	
	while(i<prg_list_size(list))//intial<cid
	{
	
		
		//cout<<i<<" "<<prg_list_size(list)<<"\n";
		intial=temp->Clusterid;
			while(intial==temp->Clusterid)
	
		{
			
				c=new comer();//to be inserted into members list and to know whether it is new comer or not
				//cout<<"size"<<sizeof(comer)<<sizeof(c);
				c->id=temp->Nodeid;
				c->counter=temp->counter;
				if(temp->New_comer)
					{
					c->New=true;
					comer_count++;
					}
				else
					c->New=false;
				
				
			prg_list_insert(part_list,c,j);// insert non first noise
	
			i++;
			j++;
				
			if(i==prg_list_size(list))
				{
			
					break;
				}
			
			temp=(coord *)prg_list_access(list,i);
			}
			
			
				
			//elect_head(part_list);// send ckey,symkey(add intial parameter to know no of cluster
		
			recev_list[id_iter]=elect_head(part_list);
			overh_list[id_iter]=recev_list[id_iter];
			comer_list[id_iter]=recev_list[id_iter];
			head_count++;
			id_iter+=2;	
				 j=0;							//to change cluster and sym key /cluster
				 prg_list_free(part_list);
				 prg_list_init(part_list);
			
				// }
				
			 continue;
				 
	
			}
		

				expec=prg_list_size(cluster_list)-head_count-noise_count;
					//cout<<"noise"<<noise_count<<"exp"<<expec<<"\n";
				//cout<<"comer"<<comer_count<<"\n";
	
				op_stat_write(head_per_stathandle ,head_count);
				
				
		FOUT; 
		
	
	}

void send_head(int id,Prg_List * list)
	{
	//1)send to head
	//a)msg type head 
	//b)send sym and cluster key and cluster members
		Objid procid;
		
		unsigned char * ch;
		Packet * pkptr;
		comer* c;
		int i,size_list=0;// to count the times we call the read file
		pkptr=op_pk_create(0);
		msg_info * msg=new msg_info();
		msg->type=head;
		msg->info=op_prg_list_create();
		prg_list_init(msg->info);
		
		read_file(counter);
		
		
		
		for(i=0;i<16;i++)
		{
			
		ch=&file[counter][i];
		
		prg_list_insert(msg->info,ch,i);// copy clus key
		
		}
		
		/*for(i=0;i<16;i++)
			{
			ch=(unsigned char *)prg_list_access(msg->info,i);
			printf("%x",*ch);
			}
		cout<<"\n";*/
		for(i=16;i<32;i++)
		{
		
		ch=&file[counter+1][i-16];
		prg_list_insert(msg->info,ch,i);// copy sym key
		}

		counter+=2;
		row+=2;

		for(i=0;i<prg_list_size(list);i++)
		{
			size_list++;
		 c=(comer *)prg_list_access(list,i);
		prg_list_insert (msg->info, c,i+32);// copy cluster members
		}
		op_pk_fd_set (pkptr, 0, OPC_FIELD_TYPE_STRUCT, msg, sizeof(msg_info)*8,op_prg_mem_copy_create,op_prg_mem_free,sizeof(msg_info));
		procid=op_id_from_name(id,OPC_OBJTYPE_PROC,"traf_src");
		
		op_pk_deliver(pkptr,procid,0);
		//total_size+=32*8+(size_list*64);
		//cout<<id<<" "<<size_list<<" "<<total_size<<"\n";
		
		
}


void reset_comer(Prg_List * list)// determine the new comers to cluster and reset them 
									//for new check
	
{
//cout<<"reset comer"<<"\n";
	coord * temp;
	for(int i=0;i<prg_list_size(list);i++)
		{
		temp=(coord *)prg_list_access(list,i);
		if(temp->New_comer)
			temp->New_comer=false;
			
		}
	
	
}



void read_file(int count)
	
{


//int j=0;
//unsigned char * ch;

list = op_prg_gdf_read ("dfile");

word_list_ptr = op_prg_str_decomp((const char*)(op_prg_list_access(list,row)),",");


convert_hex(word_list_ptr,file[count]);
/*for(int i=0;i<16;i++)
	{
	
				 
	printf("%x",file[count]);
	}		
		cout<<"\n";*/
	
word_list_ptr = op_prg_str_decomp((const char*)(op_prg_list_access(list,1+row)),",");
		
convert_hex(word_list_ptr,file[count+1]);
		

prg_list_free(word_list_ptr);
prg_mem_free(word_list_ptr);


		
prg_list_free(list);
prg_mem_free(list);
//cout<<"read file"<<"\n";
	
}


void convert_hex(Prg_List * list,unsigned char arr[])
{
		int pos=0,j=0;
	unsigned char temp,ch;
		const char *clist;
		
	while(j<prg_list_size(list))
		{
		temp=0x00;
		ch=0x00;
		
		
		for(int i=0;i<2;i++)
		{
		
		clist=(const char *)prg_list_access(list,j);
		if(*clist>='0' && *clist<='9')
           ch= (ch) | ( *clist - '0');
        else if( *clist>='a' &&  *clist<='f') // lower case
            ch= (ch) |( *clist - 'a' + 10);
		 else if( *clist>='A' &&  *clist<='F') // lower case
            ch= (ch) |( *clist - 'A' + 10);
      
		j++;
		if(i==1)
			break;
		temp=ch;
		ch=0x00;
		
		}
		
		ch=(temp<<4)|ch;
		arr[pos]=ch;
		pos++;
		}
		
		
}

void reset_malcious(Prg_List * list)
	
	{
	//cout<<"reset malc "<<"\n";
		int *x;
		coord * s;
		x=(int *)prg_list_access(list,0);
		//cout<<"malc "<<*x<<"\n";
	for(int i=0;i<prg_list_size(cluster_list);i++)
		{
		s=(coord *)prg_list_access(cluster_list,i);
		if(s->Nodeid==*x)
			{
			
			//cout<<"id "<<s->Clusterid<<"\n";
			s->New_comer=true;
			break;
			}
		}	
	
	}


// FORM NEW CLUSTER WITH NOISE POINTS if they are >=minpnts

void form_cluster(Prg_List * nos_list)// list is noise_list
{
//1) ***take noise list which consist  of noise points with thier pos in cluster_list

// 2)insert all points in cluster_list with new cid

	
	
	//cout<<"form cluster"<<"\n";
	//cout<<cid<<"\n";
	
	for(int i=0;i<prg_list_size(nos_list);i++)
	{
	
	coord * temp=(coord *)prg_list_access(nos_list,i);
	//cout<<temp->Nodeid<<" "<<"\n";
	temp->Clusterid=cid;
	temp->change=false;
	prg_list_remove(cluster_list,temp->pos-i);// remove main noise point from cluster list
	prg_list_insert_sorted(cluster_list,temp,compare);
	//cout<<"form"<<temp->Nodeid<<" "<<temp->Clusterid<<"\n";
	
	}
	

	
	/*for ( int i = 0; i< prg_list_size(cluster_list); i++)
		{		
		coord *temp=(coord *)prg_list_access(cluster_list,i);
		cout<<i<<")"<<temp->Nodeid<<" "<<temp->Clusterid<<"\n";
		}*/
	
cid++;
	
}

void check_part(Prg_List * list)
	{
	
	int intial;
	int i=0, j=0;
	
	coord * temp,*s;

	Prg_List*	part_list=prg_list_create();
	prg_list_init(part_list);

	
	temp=(coord *)prg_list_access(list,i);//skip noise
	
		while(temp->Clusterid==Noise)
			{
			i++;
			temp=(coord *)prg_list_access(list,i);
			
		 	continue;	
			}
	
	
	
	while(i<prg_list_size(list))//intial<cid
	{
	
	intial=temp->Clusterid;
	//if(temp->Clusterid==intial)
			while(intial==temp->Clusterid)
	
		{
				
			prg_list_insert(part_list,temp,j);// insert non first noise
	
			i++;
			j++;
				
			if(i==prg_list_size(list))
				{
			
					break;
				}
			
			temp=(coord *)prg_list_access(list,i);
		}
			
				if(prg_list_size(part_list)<minpnt)  
				{
				for( int k=0;k<prg_list_size(part_list);k++)
					{
					s=(coord *)prg_list_access(part_list,k);
					//cout<<s->Nodeid<<" "<<s->Clusterid<<"\n";
					s->Clusterid=Noise;
					s->counter=prg_list_size(part_list);
					prg_list_remove(list,i-prg_list_size(part_list)+k);
					prg_list_insert_sorted(list,s,compare);
					ncount++;
					}
				}	

			
				 j=0;							//to change cluster and sym key /cluster
				 prg_list_free(part_list);
				 prg_list_init(part_list);
				
			 continue;
				 
	
	}
		  
	}
	
bool check_noiselist(Prg_List *list)
	
{

coord * temp;
Objid procid;
bool * flag,check=false;
for(int i=0;i<prg_list_size(list);i++)
{	
	temp=(coord*)prg_list_access(list,i);
	procid = op_id_from_name(temp->Nodeid,OPC_OBJTYPE_PROC,"traf_src");
	flag=(bool *)op_ima_obj_svar_get(procid,"misbehave");
	if(*flag)
		{
		prg_list_remove(list,i);
		i--;
		//cout<<"in check noise "<<temp->Nodeid<<" ";
		}
}

if(prg_list_size(list)+1>=minpnt)
	
	check=true;
	
	return check; 
	
	
}


bool check_node(coord *s)
{

Objid procid;
bool * flag,check=false;

	procid = op_id_from_name(s->Nodeid,OPC_OBJTYPE_PROC,"traf_src");
	flag=(bool *)op_ima_obj_svar_get(procid,"misbehave");

	if(!(*flag))// not malic
		check=true;


return check;
		
}

int check_neigh(coord* s,Prg_List * list)
	
	{
	
	Prg_List * temp_list=prg_list_create();
	prg_list_init(temp_list);
	coord * d;
	int * i;
	
		int j=0,iter,*num,*intial,max=-1;// track number of noise
	

		while(true)
			
			{
			d=(coord *)prg_list_access(list,j);
			if(d->Clusterid==Noise)
				{
				j++;
				continue;
				}
			
			break;
			}
	
			intial=new int;
			num=new int;
			*intial=d->Clusterid;
		
			*num=1;
			while(*intial==d->Clusterid)
				{
				
				j++;
						
				if(j>=prg_list_size(list))
							break;
						
			
					 d=(coord *)prg_list_access(list,j);
					
					if(*intial!=d->Clusterid)
						{
						
						prg_list_insert(temp_list,intial,PRGC_LISTPOS_TAIL);
						prg_list_insert(temp_list,num,PRGC_LISTPOS_TAIL);
						intial=new int;
						*intial=d->Clusterid;
						num=new int;
						*num=1;
						
						}
						
						else
							*num=*num+1;
				}

			
			prg_list_insert(temp_list,intial,PRGC_LISTPOS_TAIL);
			prg_list_insert(temp_list,num,PRGC_LISTPOS_TAIL);
			
			
			for(j=1;j<prg_list_size(temp_list);j+=2)
				{
				
					i=(int *)prg_list_access(temp_list,j);
					if(*i>max)
						{
						max=*i;
						iter=j;
						}
				
				}
			
			i=(int *)prg_list_access(temp_list,iter);
			s->counter=*i;
			i=(int *)prg_list_access(temp_list,iter-1);
			return *i;		
	}
			


void store_recev(Prg_List * list)
	
{

int * x;

x=(int *)prg_list_access(list,0);

for(int i=0;i<25;i++)
	{

if(recev_list[i]==*x)
	{
		
		recev_list[++i]+=1;
		break;	
			
	}
else
	i++;

}
}

void store_comer(Prg_List * list)
	
{

int * x;

x=(int *)prg_list_access(list,0);

for(int i=0;i<25;i++)
	{

if(comer_list[i]==*x)
	{
		
		comer_list[++i]+=1;
		break;	
			
	}
else
	i++;

}
}
void store_overhead(Prg_List * list)
	
{

int * x;

x=(int *)prg_list_access(list,0);

for(int i=0;i<25;i++)
	{

if(overh_list[i]==*x)
	{
		
	x=(int *)prg_list_access(list,1);
		overh_list[++i]+=*x;
		break;	
			
	}
else
	i++;

}
}


void change_stat()
	{
	head_count=0;
	noise_count=0;
	mem_count=0;
	overh=0;
	id_iter=0;
	comer_count=0;
	actual_comer=0;
	for(int i=0;i<25;i++)
		{
		recev_list[i]=0;
		overh_list[i]=0;
		comer_list[i]=0;
		}
	}

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
#undef bits_rcvd_stathandle
#undef bitssec_rcvd_stathandle
#undef pkts_rcvd_stathandle
#undef pktssec_rcvd_stathandle
#undef ete_delay_stathandle
#undef bits_rcvd_gstathandle
#undef bitssec_rcvd_gstathandle
#undef pkts_rcvd_gstathandle
#undef pktssec_rcvd_gstathandle
#undef ete_delay_gstathandle
#undef xcoord
#undef ycoord
#undef my_id
#undef proc_name
#undef own_process_record_handle
#undef start_time
#undef stop_time
#undef avail_per_stathandle
#undef head_per_stathandle
#undef noise_per_stathandle
#undef mem_per_stathandle
#undef overhead_handle
#undef success_handle

/* Access from C kernel using C linkage */
extern "C"
{
	VosT_Obtype _op_recorder_init (int * init_block_ptr);
	VosT_Address _op_recorder_alloc (VosT_Obtype, int);
	void recorder (OP_SIM_CONTEXT_ARG_OPT)
		{
		((recorder_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr))->recorder (OP_SIM_CONTEXT_PTR_OPT);
		}

	void _op_recorder_svar (void *, const char *, void **);

	void _op_recorder_diag (OP_SIM_CONTEXT_ARG_OPT)
		{
		((recorder_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr))->_op_recorder_diag (OP_SIM_CONTEXT_PTR_OPT);
		}

	void _op_recorder_terminate (OP_SIM_CONTEXT_ARG_OPT)
		{
		/* The destructor is the Termination Block */
		delete (recorder_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr);
		}


} /* end of 'extern "C"' */




/* Process model interrupt handling procedure */


void
recorder_state::recorder (OP_SIM_CONTEXT_ARG_OPT)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	FIN_MT (recorder_state::recorder ());
	try
		{
		/* Temporary Variables */
		//Packet*		pkptr;
		//double		pk_size;
		//double		ete_delay;
		int         intrpt_type;
		int intrpt_code;
		/* End of Temporary Variables */


		FSM_ENTER ("recorder")

		FSM_BLOCK_SWITCH
			{
			/*---------------------------------------------------------*/
			/** state (DISCARD) enter executives **/
			FSM_STATE_ENTER_UNFORCED (0, "DISCARD", state0_enter_exec, "recorder [DISCARD enter execs]")

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (1,"recorder")


			/** state (DISCARD) exit executives **/
			FSM_STATE_EXIT_UNFORCED (0, "DISCARD", "recorder [DISCARD exit execs]")
				FSM_PROFILE_SECTION_IN ("recorder [DISCARD exit execs]", state0_exit_exec)
				{
				//int x;
				Packet * rcvd_pkt=OPC_NIL;
				msg_info *msg=new msg_info();
				intrpt_type = op_intrpt_type ();
				if (intrpt_type==OPC_INTRPT_STRM)
					{
					
					
					rcvd_pkt=op_pk_get (op_intrpt_strm () );
					if(rcvd_pkt!=OPC_NIL)
						{
						op_pk_fd_get(rcvd_pkt,0,&msg);
						
						switch(msg->type)
						{
						case malc:
						reset_malcious(msg->info);
						break;
						
						case recev:
							store_recev(msg->info);
						
						break;
						case comer_msg:
							store_comer(msg->info);
						
						break;
						case over_head:
							store_overhead(msg->info);
						break;
						default:
						break;
						
						}
					
						}
					delete msg;
						
					op_pk_destroy (rcvd_pkt);
					}
				
				
				intrpt_code=op_intrpt_code ();
				
				/*
				// Obtain the incoming packet.	
				pkptr = op_pk_get (op_intrpt_strm ());
				
				// Caclulate metrics to be updated.		
				pk_size = (double) op_pk_total_size_get (pkptr);
				ete_delay = op_sim_time () - op_pk_creation_time_get (pkptr);
				
				// Update local statistics.				
				op_stat_write (bits_rcvd_stathandle, 		pk_size);
				op_stat_write (pkts_rcvd_stathandle, 		1.0);
				op_stat_write (ete_delay_stathandle, 		ete_delay);
				
				op_stat_write (bitssec_rcvd_stathandle, 	pk_size);
				op_stat_write (bitssec_rcvd_stathandle, 	0.0);
				op_stat_write (pktssec_rcvd_stathandle, 	1.0);
				op_stat_write (pktssec_rcvd_stathandle, 	0.0);
				
				//Update global statistics.	
				op_stat_write (bits_rcvd_gstathandle, 		pk_size);
				op_stat_write (pkts_rcvd_gstathandle, 		1.0);
				op_stat_write (ete_delay_gstathandle, 		ete_delay);
				
				op_stat_write (bitssec_rcvd_gstathandle, 	pk_size);
				op_stat_write (bitssec_rcvd_gstathandle, 	0.0);
				op_stat_write (pktssec_rcvd_gstathandle, 	1.0);
				op_stat_write (pktssec_rcvd_gstathandle, 	0.0);
				
				// Destroy the received packet.	
				op_pk_destroy (pkptr);
				
				*/
				}
				FSM_PROFILE_SECTION_OUT (state0_exit_exec)


			/** state (DISCARD) transition processing **/
			FSM_PROFILE_SECTION_IN ("recorder [DISCARD trans conditions]", state0_trans_conds)
			FSM_INIT_COND (Do_Check)
			FSM_DFLT_COND
			FSM_TEST_LOGIC ("DISCARD")
			FSM_PROFILE_SECTION_OUT (state0_trans_conds)

			FSM_TRANSIT_SWITCH
				{
				FSM_CASE_TRANSIT (0, 3, state3_enter_exec, ;, "Do_Check", "", "DISCARD", "Recheck", "tr_34", "recorder [DISCARD -> Recheck : Do_Check / ]")
				FSM_CASE_TRANSIT (1, 0, state0_enter_exec, ;, "default", "", "DISCARD", "DISCARD", "tr_31", "recorder [DISCARD -> DISCARD : default / ]")
				}
				/*---------------------------------------------------------*/



			/** state (make_cluster) enter executives **/
			FSM_STATE_ENTER_UNFORCED (1, "make_cluster", state1_enter_exec, "recorder [make_cluster enter execs]")
				FSM_PROFILE_SECTION_IN ("recorder [make_cluster enter execs]", state1_enter_exec)
				{
				add_postions();
				find_clusters();
				partition(cluster_list);
				
				//cout<<"noise_count"<<" "<<noise_count<<"\n";
				
				for ( int i = 0; i< prg_list_size(cluster_list); i++)
						{		
						coord *temp=(coord *)prg_list_access(cluster_list,i);
						temp->counter=0;
					}
				total_size=0;
				counter=0;
				
				op_intrpt_schedule_self (op_sim_time(),0);
				}
				FSM_PROFILE_SECTION_OUT (state1_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (3,"recorder")


			/** state (make_cluster) exit executives **/
			FSM_STATE_EXIT_UNFORCED (1, "make_cluster", "recorder [make_cluster exit execs]")
				FSM_PROFILE_SECTION_IN ("recorder [make_cluster exit execs]", state1_exit_exec)
				{
				
				}
				FSM_PROFILE_SECTION_OUT (state1_exit_exec)


			/** state (make_cluster) transition processing **/
			FSM_TRANSIT_FORCE (0, state0_enter_exec, ;, "default", "", "make_cluster", "DISCARD", "tr_40", "recorder [make_cluster -> DISCARD : default / ]")
				/*---------------------------------------------------------*/



			/** state (init) enter executives **/
			FSM_STATE_ENTER_UNFORCED_NOLABEL (2, "init", "recorder [init enter execs]")
				FSM_PROFILE_SECTION_IN ("recorder [init enter execs]", state2_enter_exec)
				{
				my_id    = op_id_self ();
				//my_objid    = op_topo_parent (my_objid);
				
				//cout<<"my_id"<<my_id<<"\n";
				
				/* Initilaize the statistic handles to keep	*/
				/* track of traffic sinked by this process.	*/
				
				/*bitssec_rcvd_stathandle 	= op_stat_reg ("Traffic Sink.Traffic Received (bits/sec)",		OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
				bitssec_rcvd_stathandle 	= op_stat_reg ("Traffic Sink.Traffic Received (bits/sec)",		OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
				pkts_rcvd_stathandle 		= op_stat_reg ("Traffic Sink.Traffic Received (packets)",		OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
				pktssec_rcvd_stathandle 	= op_stat_reg ("Traffic Sink.Traffic Received (packets/sec)",	OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
				ete_delay_stathandle		= op_stat_reg ("Traffic Sink.End-to-End Delay (seconds)",		OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
				
				bits_rcvd_gstathandle 		= op_stat_reg ("Traffic Sink.Traffic Received (bits)",			OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL);
				bitssec_rcvd_gstathandle 	= op_stat_reg ("Traffic Sink.Traffic Received (bits/sec)",		OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL);
				pkts_rcvd_gstathandle 		= op_stat_reg ("Traffic Sink.Traffic Received (packets)",		OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL);
				pktssec_rcvd_gstathandle 	= op_stat_reg ("Traffic Sink.Traffic Received (packets/sec)",	OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL);
				
				ete_delay_gstathandle		= op_stat_reg ("Traffic Sink.End-to-End Delay (seconds)",		OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL);
				*/
				avail_per_stathandle = op_stat_reg ("Traffic Sink.avail",OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
				head_per_stathandle = op_stat_reg ("Traffic Sink.head",OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
				mem_per_stathandle = op_stat_reg ("Traffic Sink.member",OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
				noise_per_stathandle = op_stat_reg ("Traffic Sink.noise",OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
				success_handle = op_stat_reg ("Traffic Sink.success",OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
				overhead_handle = op_stat_reg ("Traffic Sink.Overhead",OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
				Objid	my_node_objid    = op_topo_parent (my_id);
				//cout<<"my_node_id"<<my_node_objid<<"\n";
				
				Objid	my_subnet_objid  = op_topo_parent (my_node_objid);
				//cout<<"my_subnet_id"<<my_subnet_objid<<"\n";
				//make intial cluster
				create_list();
				 check=0;
				
				
				noise_list=prg_list_create();
				prg_list_init(noise_list);
				
				
					
				
				//wait for the nodes to take their poistions
				op_intrpt_schedule_self (op_sim_time()+1,0);
				
				for(int i=0;i<16;i++)
					recev_list[i]=0;
				
				for (int i = 30 ;i<5*60 ; i +=30)
				{
						
							op_intrpt_schedule_self (i,Check);	
							
				}
				
				//cout<<index<<"\n";
				}
				FSM_PROFILE_SECTION_OUT (state2_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (5,"recorder")


			/** state (init) exit executives **/
			FSM_STATE_EXIT_UNFORCED (2, "init", "recorder [init exit execs]")


			/** state (init) transition processing **/
			FSM_TRANSIT_FORCE (1, state1_enter_exec, ;, "default", "", "init", "make_cluster", "tr_37", "recorder [init -> make_cluster : default / ]")
				/*---------------------------------------------------------*/



			/** state (Recheck) enter executives **/
			FSM_STATE_ENTER_FORCED (3, "Recheck", state3_enter_exec, "recorder [Recheck enter execs]")
				FSM_PROFILE_SECTION_IN ("recorder [Recheck enter execs]", state3_enter_exec)
				{
				check++;
				
				for (int i = 0; i< prg_list_size(cluster_list); i++)
						{
						 temp=(coord *)prg_list_access(cluster_list,i);
						 op_ima_obj_attr_get_dbl(temp->Nodeid, "x position", &xcoord);
						 op_ima_obj_attr_get_dbl(temp->Nodeid, "y position", &ycoord);
						 
						 diff1=xcoord-temp->xpos;
						 diff2=ycoord-temp->ypos;
						 
						if(abs(diff1)+abs(diff2)!=0)	
							{	
							temp->xpos=xcoord;
							temp->ypos=ycoord;
							
							temp->change=true;
							
							}
						}
				
				
				/*for ( int i = 0; i< head_count*2; i++)
					{
					//cout<<"new recev_count";
					cout<<recev_list[i]<<"  "<<"\n";
					}*/
				
				for ( int k = 1; k< head_count*2; k+=2)
					{
					mem_count+=recev_list[k]+1;
					//cout<<"recev_l"<<recev_list[k]<<"\n";
					
					}
				
				//cout<<"mem"<<mem_count<<"\n";
				op_stat_write(mem_per_stathandle ,mem_count);
				avail=(double)mem_count/(double)prg_list_size(cluster_list);
				op_stat_write(avail_per_stathandle ,avail);
				for ( int k = 1; k< head_count*2; k+=2)
					{
					overh+=overh_list[k];
					//cout<<"over"<<overh_list[k]<<"\n";
					
					}
				op_stat_write(overhead_handle ,overh);
				
				for ( int k = 1; k< head_count*2; k+=2)
					{
					actual_comer+=comer_list[k];
					
					}
				
					
				success=(double)(actual_comer)/(double)comer_count;
				if(comer_count==0)
					success=1;
					
				op_stat_write(success_handle ,success);
				//cout<<"succ"<<success<<"\n";
				
				change_stat();
				
				Recheck_cluster(cluster_list);
				
				check_part(cluster_list);
				
				scan_noise(cluster_list);
				
				ncount=0;
				partition(cluster_list);
				
				
				for ( int i = 0; i< prg_list_size(cluster_list); i++)
					{		
						coord *temp=(coord *)prg_list_access(cluster_list,i);
						temp->counter=0;
					
					
					}
					
				//cout<<"check"<<check<<"\n";
				
				counter=0;
				reset_comer(cluster_list);
				
				/*for ( int i = 0; i< prg_list_size(cluster_list); i++)
					{		
						coord *temp=(coord *)prg_list_access(cluster_list,i);
						
						cout<<temp->Clusterid<<"\n";
						
					}*/
						
				}
				FSM_PROFILE_SECTION_OUT (state3_enter_exec)

			/** state (Recheck) exit executives **/
			FSM_STATE_EXIT_FORCED (3, "Recheck", "recorder [Recheck exit execs]")


			/** state (Recheck) transition processing **/
			FSM_TRANSIT_FORCE (0, state0_enter_exec, ;, "default", "", "Recheck", "DISCARD", "tr_42", "recorder [Recheck -> DISCARD : default / ]")
				/*---------------------------------------------------------*/



			}


		FSM_EXIT (2,"recorder")
		}
	catch (...)
		{
		Vos_Error_Print (VOSC_ERROR_ABORT,
			(const char *)VOSC_NIL,
			"Unhandled C++ exception in process model (recorder)",
			(const char *)VOSC_NIL, (const char *)VOSC_NIL);
		}
	}




void
recorder_state::_op_recorder_diag (OP_SIM_CONTEXT_ARG_OPT)
	{
	/* No Diagnostic Block */
	}

void
recorder_state::operator delete (void* ptr)
	{
	FIN (recorder_state::operator delete (ptr));
	Vos_Poolmem_Dealloc (ptr);
	FOUT
	}

recorder_state::~recorder_state (void)
	{

	FIN (recorder_state::~recorder_state ())


	/* No Termination Block */


	FOUT
	}


#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE

#define FIN_PREAMBLE_DEC
#define FIN_PREAMBLE_CODE

void *
recorder_state::operator new (size_t)
#if defined (VOSD_NEW_BAD_ALLOC)
		throw (VOSD_BAD_ALLOC)
#endif
	{
	void * new_ptr;

	FIN_MT (recorder_state::operator new ());

	new_ptr = Vos_Alloc_Object (recorder_state::obtype);
#if defined (VOSD_NEW_BAD_ALLOC)
	if (new_ptr == VOSC_NIL) throw VOSD_BAD_ALLOC();
#endif
	FRET (new_ptr)
	}

/* State constructor initializes FSM handling */
/* by setting the initial state to the first */
/* block of code to enter. */

recorder_state::recorder_state (void) :
		_op_current_block (4)
	{
#if defined (OPD_ALLOW_ODB)
		_op_current_state = "recorder [init enter execs]";
#endif
	}

VosT_Obtype
_op_recorder_init (int * init_block_ptr)
	{
	FIN_MT (_op_recorder_init (init_block_ptr))

	recorder_state::obtype = Vos_Define_Object_Prstate ("proc state vars (recorder)",
		sizeof (recorder_state));
	*init_block_ptr = 4;

	FRET (recorder_state::obtype)
	}

VosT_Address
_op_recorder_alloc (VosT_Obtype, int)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	recorder_state * ptr;
	FIN_MT (_op_recorder_alloc ())

	/* New instance will have FSM handling initialized */
#if defined (VOSD_NEW_BAD_ALLOC)
	try {
		ptr = new recorder_state;
	} catch (const VOSD_BAD_ALLOC &) {
		ptr = VOSC_NIL;
	}
#else
	ptr = new recorder_state;
#endif
	FRET ((VosT_Address)ptr)
	}



void
_op_recorder_svar (void * gen_ptr, const char * var_name, void ** var_p_ptr)
	{
	recorder_state		*prs_ptr;

	FIN_MT (_op_recorder_svar (gen_ptr, var_name, var_p_ptr))

	if (var_name == OPC_NIL)
		{
		*var_p_ptr = (void *)OPC_NIL;
		FOUT
		}
	prs_ptr = (recorder_state *)gen_ptr;

	if (strcmp ("bits_rcvd_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->bits_rcvd_stathandle);
		FOUT
		}
	if (strcmp ("bitssec_rcvd_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->bitssec_rcvd_stathandle);
		FOUT
		}
	if (strcmp ("pkts_rcvd_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->pkts_rcvd_stathandle);
		FOUT
		}
	if (strcmp ("pktssec_rcvd_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->pktssec_rcvd_stathandle);
		FOUT
		}
	if (strcmp ("ete_delay_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->ete_delay_stathandle);
		FOUT
		}
	if (strcmp ("bits_rcvd_gstathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->bits_rcvd_gstathandle);
		FOUT
		}
	if (strcmp ("bitssec_rcvd_gstathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->bitssec_rcvd_gstathandle);
		FOUT
		}
	if (strcmp ("pkts_rcvd_gstathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->pkts_rcvd_gstathandle);
		FOUT
		}
	if (strcmp ("pktssec_rcvd_gstathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->pktssec_rcvd_gstathandle);
		FOUT
		}
	if (strcmp ("ete_delay_gstathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->ete_delay_gstathandle);
		FOUT
		}
	if (strcmp ("xcoord" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->xcoord);
		FOUT
		}
	if (strcmp ("ycoord" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->ycoord);
		FOUT
		}
	if (strcmp ("my_id" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->my_id);
		FOUT
		}
	if (strcmp ("proc_name" , var_name) == 0)
		{
		*var_p_ptr = (void *) (prs_ptr->proc_name);
		FOUT
		}
	if (strcmp ("own_process_record_handle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->own_process_record_handle);
		FOUT
		}
	if (strcmp ("start_time" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->start_time);
		FOUT
		}
	if (strcmp ("stop_time" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->stop_time);
		FOUT
		}
	if (strcmp ("avail_per_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->avail_per_stathandle);
		FOUT
		}
	if (strcmp ("head_per_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->head_per_stathandle);
		FOUT
		}
	if (strcmp ("noise_per_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->noise_per_stathandle);
		FOUT
		}
	if (strcmp ("mem_per_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->mem_per_stathandle);
		FOUT
		}
	if (strcmp ("overhead_handle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->overhead_handle);
		FOUT
		}
	if (strcmp ("success_handle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->success_handle);
		FOUT
		}
	*var_p_ptr = (void *)OPC_NIL;

	FOUT
	}

