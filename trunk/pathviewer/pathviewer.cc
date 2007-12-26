/*
 * pathviewer.cc
 *
 * Copyright (C) 2007 Carillon Information Security Inc.
 *
 * This library is covered by the LGPL, please read LICENSE for details.
 */
#include <glade/glade.h>
#include <gtk/gtk.h>

#include <cert.h>
#include <nspr.h>
#include <nss.h>
#include <pk11func.h>

#include <libpathfinder-nss.h>
#include <libpathfinder.h>

#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>

#include "version.h"

static char *certhex = NULL;
static GtkImage *status_image = NULL;
static GtkLabel *status_label = NULL;


static void refresh_cert_validity()
{
    assert(status_image && status_label);

    if (!certhex)
        return;

    char *errmsg;
    if (pathfinder_dbus_verify(certhex, "2.5.29.32.0", 0, 0, &errmsg))
    {
        gtk_image_set_from_stock(status_image, GTK_STOCK_YES, 
                                 GTK_ICON_SIZE_SMALL_TOOLBAR);
        gtk_label_set_text(status_label, "Validation succeeded.");
    }
    else
    {
        gtk_image_set_from_stock(status_image, GTK_STOCK_NO, 
                                 GTK_ICON_SIZE_SMALL_TOOLBAR);
        GString *errstring = g_string_new(NULL);
        g_string_printf(errstring, "Validation failed: %s.", errmsg);
        free(errmsg);

        gtk_label_set_text(status_label, errstring->str);
        g_string_free(errstring, TRUE);
    }
}


static gboolean delete_event(GtkWidget *widget, GdkEvent *event, gpointer data)
{
    return FALSE;
}


static void destroy(GtkWidget *widget, gpointer data)
{
    gtk_main_quit ();
}


static void open_file(GtkWidget *widget, gpointer data)
{
    GtkListStore *store = GTK_LIST_STORE(data);

    GtkWidget *filew = gtk_file_chooser_dialog_new("Open Certificate", NULL, 
                                                   GTK_FILE_CHOOSER_ACTION_OPEN,
                                                   GTK_STOCK_CANCEL, 
                                                   GTK_RESPONSE_CANCEL,
                                                   GTK_STOCK_OPEN, 
                                                   GTK_RESPONSE_ACCEPT,
                                                   NULL);

    if (gtk_dialog_run(GTK_DIALOG(filew)) == GTK_RESPONSE_ACCEPT)
    {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(filew));
        gtk_widget_destroy(filew);

        struct stat st;
        FILE *fp;
        if (stat(filename, &st) != 0 || !(fp = fopen(filename, "r")))
        {
            GtkWidget *msg = gtk_message_dialog_new(NULL, 
                                                    GTK_DIALOG_DESTROY_WITH_PARENT, 
                                                    GTK_MESSAGE_ERROR,
                                                    GTK_BUTTONS_CLOSE, 
                                                    "Unable to open file.");
            gtk_dialog_run(GTK_DIALOG(msg));
            gtk_widget_destroy(GTK_WIDGET(msg));
            return;
        }
                
        char buf[st.st_size];
        fread(buf, st.st_size, 1, fp);
        fclose(fp);
        g_free(filename);
        
        CERTCertificate *cert = CERT_DecodeCertFromPackage(buf, st.st_size);
        if (!cert)
        {
            GtkWidget *msg = gtk_message_dialog_new(NULL, 
                                                    GTK_DIALOG_DESTROY_WITH_PARENT, 
                                                    GTK_MESSAGE_ERROR,
                                                    GTK_BUTTONS_CLOSE, 
                                                    "Unable to load certificate from file.");
            gtk_dialog_run(GTK_DIALOG(msg));
            gtk_widget_destroy(GTK_WIDGET(msg));
            return;
        }

        PORT_Free(certhex);
        certhex = CERT_Hexify(&(cert->derCert), 0);

        gtk_list_store_clear(store);

        GtkTreeIter iter;
        gtk_list_store_append(store, &iter); 
        gtk_list_store_set(store, &iter,
                           0, "Subject",
                           1, cert->subjectName, 
                           -1);  

        gtk_list_store_append(store, &iter); 
        gtk_list_store_set(store, &iter,
                           0, "Issuer",
                           1, cert->issuerName, 
                           -1);  

        char *hexified_serial = CERT_Hexify(&(cert->serialNumber), 1);
        gtk_list_store_append(store, &iter); 
        gtk_list_store_set(store, &iter,
                           0, "Serial Number",
                           1, hexified_serial, 
                           -1);  
        PORT_Free(hexified_serial);

        refresh_cert_validity();

        return;
    }
    
    gtk_widget_destroy(filew);
}


static void refresh(GtkWidget *widget, gpointer data)
{
    printf("Refresh!\n");
    refresh_cert_validity();
}


static void about(GtkWidget *widget, gpointer data)
{
    GtkAboutDialog *aboutw = GTK_ABOUT_DIALOG(gtk_about_dialog_new());
    gtk_about_dialog_set_version(aboutw, PATHVIEWER_VERSION);
    gtk_about_dialog_set_copyright(aboutw, "Copyright (C) 2007 Carillon Information Security Inc.");
    gtk_dialog_run(GTK_DIALOG(aboutw));

    gtk_widget_destroy(GTK_WIDGET(aboutw));
}


int main(int argc, char *argv[])
{
    gtk_init(&argc, &argv);
    g_set_application_name("Pathviewer");

    // Initialize NSS
    PR_Init(PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 1);
    SECStatus secstatus = NSS_NoDB_Init(".");
    if (secstatus != SECSuccess)
    {
        fprintf(stderr, "Cannot initialize NSS!\n");
        exit(1);
    }

    GladeXML *xml = glade_xml_new("pathviewer.glade", NULL, NULL);

    GtkWidget *window = glade_xml_get_widget(xml, "window1");

    GtkWidget *treeview = glade_xml_get_widget(xml, "treeview1");
    GtkListStore *store = gtk_list_store_new(2, G_TYPE_STRING, G_TYPE_STRING);
    gtk_tree_view_set_model(GTK_TREE_VIEW(treeview), GTK_TREE_MODEL(store));

    GtkCellRenderer *renderer1 = gtk_cell_renderer_text_new();
    GtkTreeViewColumn *column1 = gtk_tree_view_column_new_with_attributes("Attribute",
                                                                         renderer1,
                                                                          "text", 0,
                                                                          NULL);
    GtkTreeViewColumn *column2 = gtk_tree_view_column_new_with_attributes("Value",
                                                                          renderer1,
                                                                          "text", 1,
                                                                          NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), column1);
    gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), column2);

    status_image = GTK_IMAGE(glade_xml_get_widget(xml, "status-image"));
    status_label = GTK_LABEL(glade_xml_get_widget(xml, "status-label"));

    g_signal_connect(G_OBJECT(window), "delete_event", 
                     G_CALLBACK(delete_event), NULL);
    g_signal_connect(G_OBJECT(window), "destroy", G_CALLBACK(destroy), NULL);
    
    GtkMenuItem *quit_item = GTK_MENU_ITEM(glade_xml_get_widget(xml, "quit-item"));
    g_signal_connect(G_OBJECT(quit_item), "activate", G_CALLBACK(destroy), 
                     NULL);

    GtkMenuItem *open_item = GTK_MENU_ITEM(glade_xml_get_widget(xml, "open-item"));
    GtkToolButton *open_button = GTK_TOOL_BUTTON(glade_xml_get_widget(xml, "open-button"));
    g_signal_connect(G_OBJECT(open_item), "activate", G_CALLBACK(open_file), 
                     store);
    g_signal_connect(G_OBJECT(open_button), "clicked", G_CALLBACK(open_file),
                     store);


    GtkMenuItem *refresh_item = GTK_MENU_ITEM(glade_xml_get_widget(xml, "refresh-item"));
    GtkToolButton *refresh_button = GTK_TOOL_BUTTON(glade_xml_get_widget(xml, "refresh-button"));
    g_signal_connect(G_OBJECT(refresh_item), "activate", G_CALLBACK(refresh), 
                     NULL);
    g_signal_connect(G_OBJECT(refresh_button), "clicked", G_CALLBACK(refresh),
                     NULL);

    GtkMenuItem *about_item = GTK_MENU_ITEM(glade_xml_get_widget(xml, "about-item"));
    g_signal_connect(G_OBJECT(about_item), "activate", G_CALLBACK(about), 
                     NULL);

    gtk_widget_show_all(window);
 
    gtk_main();

    return 0;
}
