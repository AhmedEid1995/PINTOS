/************************
modifiedBy:shehab
Phase:1
part :advanced scheduling
*************************/
//convert fraction values to integers operations
#define f (1<<14)
//convert floating number into shifted integer
#define cnvrt_n_to_x(n) (n*f)
//convert floating number into integer
#define trunk_x_to_n(x) (x/f)
//convert floating number into nearest integer
#define round_x_to_nearest_n(x) (x>=0 ? ((x+f/2)/f) : ((x-f/2)/f))
//add two floating number shifted into integer
#define add_x_and_y(x,y) (x+y)
//subtract two floating number shifted into integer
#define sub_y_from_x(x,y) (x-y)
//add floating number shifted into integer and (n shifted by fraction value)
#define add_x_and_n(x,n) (x+n*f)
//subtract floating number shifted into integer and (n shifted by fraction value)
#define sub_n_from_x(x,n) (x-n*f)
//multiply two floating number shifted into integer
#define mul_x_and_y(x,y) ((int)(((int64_t)x)*y/f))
//mutiply floating number shifted into integer and an integer
#define mul_x_and_n(x,n) (x*n)
//divide two floating number shifted into integer
#define div_x_by_y(x,y) ((int)(((int64_t)x)*f/y))
//divide floating number shifted into integer and an integer
#define div_x_by_n(x,n) (x/n)

/************************/
